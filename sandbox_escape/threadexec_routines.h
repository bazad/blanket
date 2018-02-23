#ifndef SANDBOX_ESCAPE__THREADEXEC_ROUTINES_H_
#define SANDBOX_ESCAPE__THREADEXEC_ROUTINES_H_

#include "threadexec/threadexec.h"

/*
 * threadexec_task_for_pid_remote
 *
 * Description:
 * 	A threadexec wrapper for task_for_pid(). The task port is not copied to the current task.
 */
bool threadexec_task_for_pid_remote(threadexec_t threadexec, int pid, mach_port_t *task_remote);

/*
 * threadexec_host_set_exception_ports
 *
 * Description:
 * 	A wrapper around host_set_exception_ports().
 */
bool threadexec_host_set_exception_ports(
		threadexec_t          threadexec,
		mach_port_t           host_priv,
		exception_mask_t      exception_mask,
		mach_port_t           exception_port,
		exception_behavior_t  behavior,
		thread_state_flavor_t flavor);

/*
 * threadexec_task_mach_port_names
 *
 * Description:
 * 	A wrapper around mach_port_names(). To clean up, free the names array.
 */
bool threadexec_task_mach_port_names(threadexec_t threadexec, task_t task_remote,
		mach_port_name_t **names, mach_port_type_t **types, size_t *count);

/*
 * threadexec_task_get_send_right_name
 *
 * Description:
 * 	Get a task's name for a send right in the current task.
 */
bool threadexec_task_get_send_right_name(threadexec_t threadexec, task_t task_remote,
		mach_port_t port, mach_port_t *port_name);

/*
 * threadexec_task_mach_port_insert_right
 *
 * Description:
 * 	A wrapper around mach_port_insert_right.
 */
bool threadexec_task_mach_port_insert_right(threadexec_t threadexec, task_t task_remote,
		mach_port_name_t port_name, mach_port_t port_remote,
		mach_msg_type_name_t disposition);

/*
 * threadexec_task_mach_port_mod_refs
 *
 * Description:
 * 	A wrapper around mach_port_mod_refs.
 */
bool threadexec_task_mach_port_mod_refs(threadexec_t threadexec, task_t task_remote,
		mach_port_name_t port_name, mach_port_right_t right, mach_port_delta_t delta);

#endif
