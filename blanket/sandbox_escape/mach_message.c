#include "blanket/sandbox_escape/mach_message.h"

#include "blanket/log/log.h"

#include <assert.h>
#include <stdlib.h>

bool
mach_receive_message(mach_port_t port, mach_msg_timeout_t timeout,
		void (^handler)(mach_msg_header_t *msg)) {
	kern_return_t kr;
	// Loop until we get the buffer size right.
	mach_msg_header_t *msg;
	size_t msg_size = 0x1000;
	mach_msg_option_t options = MACH_RCV_MSG | MACH_RCV_LARGE
		| MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0)
		| MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT);
	if (timeout != MACH_MSG_TIMEOUT_NONE) {
		options |= MACH_RCV_TIMEOUT;
	}
	for (;;) {
		// Allocate a buffer for the message.
		msg = malloc(msg_size);
		assert(msg != NULL);
		// Try to receive the message.
		kr = mach_msg(msg,
				options,
				0,
				(mach_msg_size_t) msg_size,
				port,
				timeout,
				MACH_PORT_NULL);
		if (kr != MACH_RCV_TOO_LARGE) {
			break;
		}
		// Allocate a bigger message buffer next time. This should only happen once, if the
		// kernel doesn't like to us.
		free(msg);
		msg_size = msg->msgh_size + REQUESTED_TRAILER_SIZE(options);
	}
	// Handle any errors.
	if (kr != KERN_SUCCESS) {
		goto done;
	}
	// Process the message.
	handler(msg);
done:
	free(msg);
	return (kr == KERN_SUCCESS);
}

bool
mach_send_message(mach_msg_header_t *msg) {
	kern_return_t kr = mach_msg(msg,
			MACH_SEND_MSG,
			msg->msgh_size,
			0,
			MACH_PORT_NULL,
			MACH_MSG_TIMEOUT_NONE,
			MACH_PORT_NULL);
	if (kr != KERN_SUCCESS) {
		ERROR("%s: 0x%x", "mach_msg", kr);
	}
	return (kr == KERN_SUCCESS);
}

void
mach_mig_create_error(const mach_msg_header_t *request, mig_reply_error_t *reply,
		kern_return_t result) {
	reply->Head.msgh_bits        = MACH_MSGH_BITS_SET(MACH_MSGH_BITS_REMOTE(request->msgh_bits), 0, 0, 0);
	reply->Head.msgh_size        = sizeof(*reply);
	reply->Head.msgh_remote_port = request->msgh_remote_port;
	reply->Head.msgh_id          = request->msgh_id + 100;
	reply->NDR                   = NDR_record;
	reply->RetCode               = result;
}
