#include "sandbox_escape/threadexec_routines.h"

#include "log/log.h"

#include <assert.h>
#include <stdlib.h>

#define ERROR_REMOTE_CALL(fn)	\
	ERROR("Could not call %s in remote task", #fn)
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

bool
threadexec_host_set_exception_ports(
		threadexec_t          threadexec,
		mach_port_t           host_priv,
		exception_mask_t      exception_mask,
		mach_port_t           exception_port,
		exception_behavior_t  behavior,
		thread_state_flavor_t flavor) {
	bool success = false;
	kern_return_t kr;
	// First insert host_priv into the remote task.
	mach_port_t host_priv_r;
	bool ok = threadexec_mach_port_insert(threadexec, host_priv, &host_priv_r,
			MACH_MSG_TYPE_COPY_SEND);
	if (!ok) {
		ERROR("Could not insert host-priv port into task 0x%x",
				threadexec_task(threadexec));
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
	// Finally call host_set_exception_ports().
	ok = threadexec_call_cv(threadexec, &kr, sizeof(kr),
			host_set_exception_ports, 5,
			TX_CARG_LITERAL(mach_port_t,           host_priv_r),
			TX_CARG_LITERAL(exception_mask_t,      exception_mask),
			TX_CARG_LITERAL(mach_port_t,           exception_port_r),
			TX_CARG_LITERAL(exception_behavior_t,  behavior),
			TX_CARG_LITERAL(thread_state_flavor_t, flavor));
	if (!ok) {
		ERROR_REMOTE_CALL(host_set_exception_ports);
		goto fail_2;
	}
	if (kr != KERN_SUCCESS) {
		ERROR("Remote call to %s returned %u in task 0x%x",
				"host_set_exception_ports", kr, threadexec_task(threadexec));
		goto fail_2;
	}
	// Did it!
	success = true;
fail_2:
	threadexec_mach_port_deallocate(threadexec, exception_port_r);
fail_1:
	threadexec_mach_port_deallocate(threadexec, host_priv_r);
fail_0:
	return success;
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
