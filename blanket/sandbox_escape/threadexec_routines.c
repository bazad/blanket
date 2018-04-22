#include "blanket/sandbox_escape/threadexec_routines.h"

#include "blanket/log/log.h"
#include "headers/libproc.h"
#include "headers/mach_vm.h"

#include <assert.h>
#include <stdlib.h>
#include <sys/param.h>

#define ERROR_REMOTE_CALL_S(fn)	\
	ERROR("Could not call %s in remote task", fn)
#define ERROR_REMOTE_CALL(fn)	\
	ERROR_REMOTE_CALL_S(#fn)
#define ERROR_REMOTE_CALL_RETURN(fn, fmt, ret)	\
	ERROR("Remote call to %s returned "fmt, #fn, ret)

bool
threadexec_task_for_pid_remote(threadexec_t threadexec, int pid, mach_port_t *task_remote) {
	kern_return_t kr;
	bool ok = threadexec_call_cv(threadexec, &kr, sizeof(kr),
			task_for_pid, 3,
			TX_CARG_LITERAL(mach_port_t, threadexec_task_remote(threadexec)),
			TX_CARG_LITERAL(int, pid),
			TX_CARG_PTR_LITERAL_OUT(mach_port_t *, task_remote));
	if (!ok) {
		ERROR_REMOTE_CALL(task_for_pid);
		return false;
	}
	if (kr != KERN_SUCCESS) {
		ERROR_REMOTE_CALL_RETURN(task_for_pid, "%u", kr);
		return false;
	}
	return true;
}

// Call task_for_pid in the threadexec task and copy the port to the local task.
static bool
threadexec_task_for_pid_local_and_remote(threadexec_t threadexec, int pid,
		mach_port_t *task_l, mach_port_t *task_r) {
	// Get the task port for the process in the remote task.
	mach_port_t task_r0;
	bool ok = threadexec_task_for_pid_remote(threadexec, pid, &task_r0);
	if (!ok) {
		ERROR_REMOTE_CALL_RETURN(task_for_pid, "invalid port 0x%x", task_r0);
		goto fail_0;
	}
	// Copy the task port locally.
	ok = threadexec_mach_port_extract(threadexec, task_r0, task_l, MACH_MSG_TYPE_COPY_SEND);
	if (!ok) {
		ERROR("Could not copy task port locally");
		goto fail_1;
	}
	// Success.
	*task_r = task_r0;
	return true;
fail_1:
	threadexec_mach_port_deallocate(threadexec, task_r0);
fail_0:
	return false;
}

bool
threadexec_task_for_pid(threadexec_t threadexec, int pid, mach_port_t *task) {
	mach_port_t task_r;
	bool success = threadexec_task_for_pid_local_and_remote(threadexec, pid, task, &task_r);
	if (!success) {
		return false;
	}
	threadexec_mach_port_deallocate(threadexec, task_r);
	return true;
}

// A wrapper around {thread,task,host}_set_exception_ports().
static bool
threadexec_target_set_exception_ports_internal(
		threadexec_t          threadexec,
		const void *          implementation,
		const char *          implementation_name,
		mach_port_t           receiver,
		const char *          receiver_name,
		exception_mask_t      exception_mask,
		mach_port_t           exception_port,
		exception_behavior_t  behavior,
		thread_state_flavor_t flavor) {
	bool success = false;
	kern_return_t kr;
	// First insert the receiver port into the remote task.
	mach_port_t receiver_r;
	bool ok = threadexec_mach_port_insert(threadexec, receiver, &receiver_r,
			MACH_MSG_TYPE_COPY_SEND);
	if (!ok) {
		ERROR("Could not insert %s port into task 0x%x",
				receiver_name, threadexec_task(threadexec));
		goto fail_0;
	}
	// Next insert the exception port into the remote task.
	mach_port_t exception_port_r;
	ok = threadexec_mach_port_insert(threadexec, exception_port, &exception_port_r,
			MACH_MSG_TYPE_COPY_SEND);
	if (!ok) {
		ERROR("Could not insert exception port into task 0x%x",
				threadexec_task(threadexec));
		goto fail_1;
	}
	// Finally call {thread,task,host}_set_exception_ports().
	ok = threadexec_call_cv(threadexec, &kr, sizeof(kr),
			implementation, 5,
			TX_CARG_LITERAL(mach_port_t,           receiver_r),
			TX_CARG_LITERAL(exception_mask_t,      exception_mask),
			TX_CARG_LITERAL(mach_port_t,           exception_port_r),
			TX_CARG_LITERAL(exception_behavior_t,  behavior),
			TX_CARG_LITERAL(thread_state_flavor_t, flavor));
	if (!ok) {
		ERROR_REMOTE_CALL_S(implementation_name);
		goto fail_2;
	}
	if (kr != KERN_SUCCESS) {
		ERROR("Remote call to %s returned %u in task 0x%x",
				implementation_name, kr, threadexec_task(threadexec));
		goto fail_2;
	}
	// Did it!
	success = true;
fail_2:
	// Deallocate the exception port reference.
	threadexec_mach_port_deallocate(threadexec, exception_port_r);
fail_1:
	// Deallocate the receiver port reference.
	threadexec_mach_port_deallocate(threadexec, receiver_r);
fail_0:
	return success;
}

bool
threadexec_host_set_exception_ports(
		threadexec_t          threadexec,
		mach_port_t           host_priv,
		exception_mask_t      exception_mask,
		mach_port_t           exception_port,
		exception_behavior_t  behavior,
		thread_state_flavor_t flavor) {
	return threadexec_target_set_exception_ports_internal(
			threadexec,
			host_set_exception_ports,
			"host_set_exception_ports",
			host_priv,
			"host-priv",
			exception_mask,
			exception_port,
			behavior,
			flavor);
}

bool
threadexec_task_set_exception_ports(
		threadexec_t          threadexec,
		mach_port_t           task,
		exception_mask_t      exception_mask,
		mach_port_t           exception_port,
		exception_behavior_t  behavior,
		thread_state_flavor_t flavor) {
	return threadexec_target_set_exception_ports_internal(
			threadexec,
			task_set_exception_ports,
			"task_set_exception_ports",
			task,
			"task",
			exception_mask,
			exception_port,
			behavior,
			flavor);
}

bool
threadexec_mach_port_names(threadexec_t threadexec, task_t task_r,
		mach_port_name_t **names, mach_port_type_t **types, size_t *count) {
	bool success = false;
	// Call mach_port_names().
	mach_port_name_array_t names_r;
	mach_port_type_array_t types_r;
	mach_msg_type_number_t names_count, types_count;
	kern_return_t kr;
	bool ok = threadexec_call_cv(threadexec, &kr, sizeof(kr),
			mach_port_names, 5,
			TX_CARG_LITERAL(mach_port_t, task_r),
			TX_CARG_PTR_LITERAL_OUT(mach_port_name_array_t *, &names_r),
			TX_CARG_PTR_LITERAL_OUT(mach_msg_type_number_t *, &names_count),
			TX_CARG_PTR_LITERAL_OUT(mach_port_type_array_t *, &types_r),
			TX_CARG_PTR_LITERAL_OUT(mach_msg_type_number_t *, &types_count));
	if (!ok) {
		ERROR_REMOTE_CALL(mach_port_names);
		goto fail_0;
	}
	if (kr != KERN_SUCCESS) {
		ERROR_REMOTE_CALL_RETURN(mach_port_names, "%u", kr);
		goto fail_0;
	}
	// Now allocate a local buffer for the names and copy them in.
	size_t names_size = names_count * sizeof(*names_r);
	size_t types_size = types_count * sizeof(*types_r);
	mach_port_name_t *names_l = malloc(names_size + types_size);
	mach_port_type_t *types_l = (mach_port_type_t *) (names_l + names_count);
	ok = threadexec_read(threadexec, names_r, names_l, names_size);
	if (!ok) {
		ERROR("Could not read Mach port names array");
		goto fail_1;
	}
	ok = threadexec_read(threadexec, types_r, types_l, types_size);
	if (!ok) {
		ERROR("Could not read Mach port types array");
		goto fail_1;
	}
	// Success!
	*names = names_l;
	*types = types_l;
	*count = names_count;
	success = true;
fail_1:
	if (!success) {
		free(names_l);
	}
	threadexec_mach_vm_deallocate(threadexec, names_r, names_size);
	threadexec_mach_vm_deallocate(threadexec, types_r, types_size);
fail_0:
	return success;
}

bool
threadexec_task_get_send_right_name(threadexec_t threadexec, task_t task_remote,
		mach_port_t port, mach_port_t *port_name) {
	bool success = false;
	// First get all the mach port names.
	mach_port_t *names;
	mach_port_type_t *types;
	size_t name_count;
	bool ok = threadexec_mach_port_names(threadexec, task_remote,
			&names, &types, &name_count);
	if (!ok) {
		ERROR("Could not get port names in task 0x%x", threadexec_task(threadexec));
		goto fail_0;
	}
	// Now transfer the send right to the threadexec task.
	mach_port_t port_remote;
	ok = threadexec_mach_port_insert(threadexec, port, &port_remote, MACH_MSG_TYPE_COPY_SEND);
	if (!ok) {
		ERROR("Could not insert port 0x%x into task 0x%x",
				port, threadexec_task(threadexec));
		goto fail_1;
	}
	// Now try to insert the port into the task's address space under every possible name.
	mach_port_t port_name_in_task = MACH_PORT_NULL;
	for (size_t i = 0; i < name_count; i++) {
		// Skip it if it isn't a pure send right.
		if ((types[i] & MACH_PORT_TYPE_ALL_RIGHTS) != MACH_PORT_TYPE_SEND) {
			continue;
		}
		// Try to insert it.
		kern_return_t kr;
		ok = threadexec_call_cv(threadexec, &kr, sizeof(kr),
				mach_port_insert_right, 4,
				TX_CARG_LITERAL(mach_port_t, task_remote),
				TX_CARG_LITERAL(mach_port_name_t, names[i]),
				TX_CARG_LITERAL(mach_port_t, port_remote),
				TX_CARG_LITERAL(mach_msg_type_name_t, MACH_MSG_TYPE_COPY_SEND));
		if (!ok) {
			ERROR_REMOTE_CALL(mach_port_insert_right);
			goto fail_2;
		}
		if (kr == KERN_SUCCESS) {
			port_name_in_task = names[i];
			goto found;
		} else if (kr != KERN_NAME_EXISTS && kr != KERN_RIGHT_EXISTS) {
			ERROR_REMOTE_CALL_RETURN(mach_port_insert_right, "%u", kr);
			goto fail_2;
		}
	}
	// If we get here, the port was not found.
	ERROR("Port not found in task");
	goto fail_2;
found:
	*port_name = port_name_in_task;
	success = true;
	threadexec_call_cv(threadexec, NULL, 0,
			mach_port_deallocate, 2,
			TX_CARG_LITERAL(mach_port_t, task_remote),
			TX_CARG_LITERAL(mach_port_t, port_name_in_task));
fail_2:
	threadexec_mach_port_deallocate(threadexec, port_remote);
fail_1:
	free(names);
fail_0:
	return success;
}

bool
threadexec_task_mach_port_insert_right(threadexec_t threadexec, task_t task_remote,
		mach_port_name_t port_name, mach_port_t port_remote,
		mach_msg_type_name_t disposition) {
	kern_return_t kr;
	bool ok = threadexec_call_cv(threadexec, &kr, sizeof(kr),
			mach_port_insert_right, 4,
			TX_CARG_LITERAL(mach_port_t, task_remote),
			TX_CARG_LITERAL(mach_port_t, port_name),
			TX_CARG_LITERAL(mach_port_t, port_remote),
			TX_CARG_LITERAL(mach_msg_type_name_t, disposition));
	if (!ok) {
		ERROR_REMOTE_CALL(mach_port_insert_right);
		return false;
	}
	if (kr != KERN_SUCCESS) {
		ERROR_REMOTE_CALL_RETURN(mach_port_insert_right, "%u", kr);
		return false;
	}
	return true;
}

bool
threadexec_task_mach_port_mod_refs(threadexec_t threadexec, task_t task_remote,
		mach_port_name_t port_name, mach_port_right_t right, mach_port_delta_t delta) {
	kern_return_t kr;
	bool ok = threadexec_call_cv(threadexec, &kr, sizeof(kr),
			mach_port_mod_refs, 4,
			TX_CARG_LITERAL(mach_port_t, task_remote),
			TX_CARG_LITERAL(mach_port_t, port_name),
			TX_CARG_LITERAL(mach_port_right_t, right),
			TX_CARG_LITERAL(mach_port_delta_t, delta));
	if (!ok) {
		ERROR_REMOTE_CALL(mach_port_mod_refs);
		return false;
	}
	if (kr != KERN_SUCCESS) {
		ERROR_REMOTE_CALL_RETURN(mach_port_mod_refs, "%u", kr);
		return false;
	}
	return true;
}

bool
threadexec_list_pids_with_paths(threadexec_t threadexec, pid_t **pids, char ***paths,
		size_t *count) {
	bool success = false;
	// Call proc_listallpids(NULL, 0) to get the number of processes currently on the system.
	int capacity;
	bool ok = threadexec_call_cv(threadexec, &capacity, sizeof(count),
			proc_listallpids, 2,
			TX_CARG_LITERAL(void *, NULL),
			TX_CARG_LITERAL(int, 0));
	if (!ok || capacity <= 0) {
		ERROR("Could not get the number of PIDs");
		goto fail_0;
	}
	// Create an array in which to collect the PIDs.
	capacity += 32;
	assert(capacity > 0);
	size_t all_pids_size = capacity * sizeof(pid_t);
	pid_t *all_pids = malloc(all_pids_size);
	assert(all_pids != NULL);
	// Call proc_listallpids again to collect the PIDs.
	int all_count;
	ok = threadexec_call_cv(threadexec, &all_count, sizeof(all_count),
			proc_listallpids, 2,
			TX_CARG_PTR_DATA_OUT(void *, all_pids, all_pids_size),
			TX_CARG_LITERAL(int, all_pids_size));
	if (!ok || all_count <= 0) {
		ERROR("Could not collect the PIDs of currently running processes");
		goto fail_1;
	}
	// Now create the final memory buffer. We assume a full MAXPATHLEN for each path for
	// simplicity.
	size_t size = ((all_count + 1) & ~1) * sizeof(pid_t)
		+ all_count * sizeof(char *)
		+ all_count * MAXPATHLEN;
	pid_t *pids_array = malloc(size);
	assert(pids_array != NULL);
	char **paths_array = (char **)(pids_array + ((all_count + 1) & ~1));
	char *pathbuf = (char *)(paths_array + all_count);
	// Fill the array with the path of each PID. We walk the array in reverse because
	// proc_listallpids seems to return the PIDs in reverse order.
	size_t out_idx = 0;
	for (int i = all_count - 1; i >= 0; i--, out_idx++) {
		assert(pathbuf < (char *)pids_array + size);
		// Fill in the pids and paths array entries.
		pids_array[out_idx] = all_pids[i];
		paths_array[out_idx] = pathbuf;
		// Call proc_pidpath to get the path of the PID.
		int len;
		ok = threadexec_call_cv(threadexec, &len, sizeof(len),
				proc_pidpath, 3,
				TX_CARG_LITERAL(int, all_pids[i]),
				TX_CARG_PTR_DATA_OUT(void *, pathbuf, MAXPATHLEN),
				TX_CARG_LITERAL(uint32_t, MAXPATHLEN));
		if (!ok || len <= 0) {
			pathbuf[0] = 0;
		}
		pathbuf += MAXPATHLEN;
	}
	assert(all_count == out_idx);
	// Set the output parameters.
	*pids = pids_array;
	*paths = paths_array;
	*count = all_count;
	success = true;
fail_1:
	free(all_pids);
fail_0:
	return success;
}

bool
threadexec_pids_for_path(threadexec_t threadexec, const char *path,
		pid_t *pids, size_t *count) {
	// Get the list of all processes.
	pid_t *all_pids;
	char **all_paths;
	size_t all_count;
	bool ok = threadexec_list_pids_with_paths(threadexec, &all_pids, &all_paths, &all_count);
	if (!ok) {
		return false;
	}
	// Now copy the PIDs with a matching path into the array.
	pid_t *end = pids + *count;
	size_t matches = 0;
	for (size_t i = 0; i < all_count; i++) {
		if (strcmp(path, all_paths[i]) == 0) {
			matches++;
			if (pids < end) {
				*pids = all_pids[i];
				pids++;
			}
		}
	}
	// Set count to the number of matches.
	*count = matches;
	free(all_pids);
	return true;
}

threadexec_t
threadexec_init_with_threadexec_and_pid(threadexec_t threadexec, pid_t pid) {
	threadexec_t new_threadexec = NULL;
	// Get the task port for the process both locally and in the threadexec.
	mach_port_t task, task_r;
	bool ok = threadexec_task_for_pid_local_and_remote(threadexec, pid, &task, &task_r);
	if (!ok) {
		ERROR("Could not get task port for PID %u", pid);
		goto fail_0;
	}
	// Use the threadexec to create a thread in the process.
	kern_return_t kr;
	mach_port_t thread_r;
	ok = threadexec_call_cv(threadexec, &kr, sizeof(kr),
			thread_create, 2,
			TX_CARG_LITERAL(mach_port_t, task_r),
			TX_CARG_PTR_LITERAL_OUT(mach_port_t *, &thread_r));
	if (!ok) {
		ERROR_REMOTE_CALL(thread_create);
		goto fail_1;
	}
	if (kr != KERN_SUCCESS) {
		ERROR_REMOTE_CALL_RETURN(thread_create, "%u", kr);
		goto fail_1;
	}
	// Copy the thread locally.
	mach_port_t thread;
	ok = threadexec_mach_port_extract(threadexec, thread_r, &thread, MACH_MSG_TYPE_COPY_SEND);
	if (!ok) {
		ERROR("Could not copy thread port locally");
		goto fail_2;
	}
	// Threads created with thread_create() don't have a stack. Allocate memory for a stack in
	// the target process.
	mach_vm_address_t stack_address = 0;
	mach_vm_size_t stack_size = 0x8000;
	ok = threadexec_call_cv(threadexec, &kr, sizeof(kr),
			mach_vm_allocate, 4,
			TX_CARG_LITERAL(mach_port_t, task_r),
			TX_CARG_PTR_LITERAL_INOUT(mach_vm_address_t *, &stack_address),
			TX_CARG_LITERAL(mach_vm_size_t, stack_size),
			TX_CARG_LITERAL(int, VM_FLAGS_ANYWHERE));
	if (!ok) {
		ERROR_REMOTE_CALL(mach_vm_allocate);
		goto fail_3;
	}
	if (kr != KERN_SUCCESS) {
		ERROR_REMOTE_CALL_RETURN(mach_vm_allocate, "%u", kr);
		goto fail_3;
	}
	// Set the SP register in the new thread to the top of our new stack.
	arm_thread_state64_t state = {};
	state.__sp = stack_address + stack_size - 0x100;
	kr = thread_set_state(thread, ARM_THREAD_STATE64, (thread_state_t) &state,
			ARM_THREAD_STATE64_COUNT);
	if (kr != KERN_SUCCESS) {
		ERROR("Could not set thread state on new thread");
		goto fail_4;
	}
	// Now we have a new bare thread that we can pass to the threadexec library.
	new_threadexec = threadexec_init(task, thread, TX_BARE_THREAD | TX_KILL_THREAD);
	if (new_threadexec == NULL) {
		ERROR("Could not create execution context in PID %u", pid);
	}
fail_4:
	// TODO: Deallocate the memory on failure.
	// If we failed, terminate and deallocate the thread we created.
	if (new_threadexec == NULL) {
fail_3:
		thread_terminate(thread);
		mach_port_deallocate(mach_task_self(), thread);
	}
fail_2:
	// Deallocate the thread port in the threadexec task.
	threadexec_mach_port_deallocate(threadexec, thread_r);
	// TODO: Kill the thread via the threadexec.
fail_1:
	// Deallocate the task port in the threadexec task and, on failure, in our task.
	threadexec_mach_port_deallocate(threadexec, task_r);
	if (new_threadexec == NULL) {
		mach_port_deallocate(mach_task_self(), task);
	}
fail_0:
	return new_threadexec;
}
