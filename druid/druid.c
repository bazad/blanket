#include "druid/druid.h"

#include "launchd/launchd_service.h"
#include "log/log.h"
#include "xpc_crash/xpc_crash.h"

#include <assert.h>

// An XPC endpoint we can connect to in order to interact with druid.
static const char DRUID_SOURCE_SERVICE[] = "com.apple.DragUI.druid.source";

bool
druid_start() {
	mach_port_t druid_service = launchd_lookup_service(DRUID_SOURCE_SERVICE);
	if (druid_service == MACH_PORT_NULL) {
		ERROR("Could not look up %s", DRUID_SOURCE_SERVICE);
		return false;
	}
	union {
		mach_msg_header_t msg;
		mig_reply_error_t reply;
		uint8_t buf[0x200];
	} buf = {};
	buf.msg.msgh_bits        = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_MOVE_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE, 0, 0);
	buf.msg.msgh_size        = sizeof(buf);
	buf.msg.msgh_remote_port = druid_service;
	buf.msg.msgh_local_port  = mig_get_reply_port();
	buf.msg.msgh_id          = 0x41424142;
	kern_return_t kr = mach_msg(&buf.msg,
			MACH_SEND_MSG | MACH_RCV_MSG,
			sizeof(buf.msg),
			sizeof(buf),
			buf.msg.msgh_local_port,
			MACH_MSG_TIMEOUT_NONE,
			MACH_PORT_NULL);
	if (kr != KERN_SUCCESS) {
		WARNING("%s: %s: 0x%x", __func__, "mach_msg", kr);
		return false;
	}
	mach_msg_destroy(&buf.reply.Head);
	return true;
}

bool
druid_crash() {
	return xpc_crash(DRUID_SOURCE_SERVICE);
}
