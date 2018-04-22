#include "blanket/sandbox_escape/exception_server.h"

#include "blanket/log/log.h"
#include "blanket/sandbox_escape/mach_message.h"

#include <assert.h>

// As it turns out, when ReportCrash sends an exception message to SafetyNet, it uses an
// exception_raise message rather than a mach_exception_raise_state_identity message (the only type
// that ReportCrash can actually handle). Thus, we only need to handle that one message type.

#define EXCEPTION_RAISE		2401

typedef struct __attribute__((packed)) {
	mach_msg_header_t          Head;
	mach_msg_body_t            msgh_body;
	mach_msg_port_descriptor_t thread;
	mach_msg_port_descriptor_t task;
	NDR_record_t               NDR;
	exception_type_t           exception;
	mach_msg_type_number_t     codeCnt;
	integer_t                  code[2];
} Request__exception_raise_t;

typedef struct __attribute__((packed)) {
	mach_msg_header_t Head;
	NDR_record_t      NDR;
	kern_return_t     RetCode;
} Reply__exception_raise_t;

static bool
check_exception_raise_request(Request__exception_raise_t *request) {
	mach_msg_size_t max_size = sizeof(*request);
	mach_msg_size_t min_size = max_size - sizeof(request->code);
	if (request->Head.msgh_id != EXCEPTION_RAISE
			|| (request->Head.msgh_bits & MACH_MSGH_BITS_COMPLEX) == 0
			|| request->Head.msgh_size < min_size
			|| request->Head.msgh_size > max_size
			|| request->msgh_body.msgh_descriptor_count != 2
			|| request->thread.type != MACH_MSG_PORT_DESCRIPTOR
			|| request->thread.disposition != MACH_MSG_TYPE_PORT_SEND
			|| request->task.type != MACH_MSG_PORT_DESCRIPTOR
			|| request->task.disposition != MACH_MSG_TYPE_PORT_SEND
			|| request->codeCnt > 2) {
		return false;
	}
	mach_msg_size_t required_size = min_size + request->codeCnt * sizeof(request->code[0]);
	if (request->Head.msgh_size != required_size) {
		return false;
	}
	return true;
};

bool
catch_exception_server(mach_port_t exception_port, uint64_t timeout_ns,
		catch_exception_block_t exception_block) {
	mach_msg_timeout_t timeout_ms = MACH_MSG_TIMEOUT_NONE;
	if (timeout_ns > 0) {
		timeout_ms = (mach_msg_timeout_t) ((timeout_ns + NSEC_PER_MSEC - 1) / NSEC_PER_MSEC);
	}
	__block union {
		Reply__exception_raise_t reply;
		mig_reply_error_t        error;
	} buf = {};
	// Loop until we are told to stop.
	for (__block bool running = true; running;) {
		// Try to receive a message.
		bool received = mach_receive_message(exception_port, timeout_ms,
				^(mach_msg_header_t *msg) {
			Request__exception_raise_t *request = (Request__exception_raise_t *)msg;
			kern_return_t result = KERN_SUCCESS;
			// Make sure it's the right type of message.
			DEBUG_TRACE(1, "Received message ID 0x%x on exception port 0x%x",
					msg->msgh_id, exception_port);
			bool ok = check_exception_raise_request(request);
			if (!ok) {
				result = KERN_FAILURE;
				mach_mig_create_error(msg, &buf.error, result);
				goto send_reply;
			}
			// Process the message.
			DEBUG_TRACE(1, "Calling exception block for task 0x%x thread 0x%x",
					request->task.name, request->thread.name);
			running = !exception_block(
					request->thread.name,
					request->task.name,
					request->exception,
					request->code,
					request->codeCnt,
					&result);
			// Build the reply.
			buf.reply.Head.msgh_bits        = MACH_MSGH_BITS_SET(MACH_MSGH_BITS_REMOTE(request->Head.msgh_bits), 0, 0, 0);
			buf.reply.Head.msgh_size        = sizeof(buf);
			buf.reply.Head.msgh_remote_port = request->Head.msgh_remote_port;
			buf.reply.Head.msgh_id          = request->Head.msgh_id + 100;
			buf.reply.NDR                   = NDR_record;
			buf.reply.RetCode               = result;
			// Clean up all resources in the request except the reply port, according
			// to MIG semantics.
			assert((buf.reply.Head.msgh_bits & MACH_MSGH_BITS_COMPLEX) == 0);
			assert(result != MIG_NO_REPLY);
			if (result != KERN_SUCCESS
					&& (request->Head.msgh_bits & MACH_MSGH_BITS_COMPLEX) != 0) {
				request->Head.msgh_remote_port = MACH_PORT_NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
				mach_msg_destroy(&request->Head);
#pragma clang diagnostic pop
			}
			// Send the reply.
send_reply:;
			mach_send_message(&buf.reply.Head);
		});
		// If we couldn't receive the message, abort.
		if (!received) {
			return false;
		}
	}
	return true;
}
