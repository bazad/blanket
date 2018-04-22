#ifndef BLANKET__SANDBOX_ESCAPE__THREADEXEC_ROUTINES_H_
#define BLANKET__SANDBOX_ESCAPE__THREADEXEC_ROUTINES_H_

#include "threadexec/threadexec.h"

/*
 * threadexec_task_for_pid_remote
 *
 * Description:
 * 	A threadexec wrapper for task_for_pid(). The task port is not copied to the current task.
 */
bool threadexec_task_for_pid_remote(threadexec_t threadexec, int pid, mach_port_t *task_remote);

/*
 * threadexec_task_for_pid
 *
 * Description:
 * 	A threadexec wrapper for task_for_pid(). The task port is copied to the current task.
 */
bool threadexec_task_for_pid(threadexec_t threadexec, int pid, mach_port_t *task);

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
 * threadexec_task_set_exception_ports
 *
 * Description:
 * 	A wrapper around task_set_exception_ports().
 */
bool threadexec_task_set_exception_ports(
		threadexec_t          threadexec,
		mach_port_t           task,
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

/*
 * threadexec_list_pids_with_paths
 *
 * Description:
 * 	Get a list of all PIDs and their corresponding executable path.
 *
 * Parameters:
 * 	threadexec			The threadexec context.
 * 	pids				On return, an array of PIDs of all processes.
 * 	paths				On return, an array of the paths to the main executable of
 * 					each process.
 * 	count				On return, the number of elements in each array.
 *
 * Returns:
 * 	Returns true on success.
 *
 * Notes:
 * 	The pids array, the paths array, and the strings in the paths array all share the same
 * 	underlying allocation. When no longer needed, all the memory can be released by freeing
 * 	just the pids array.
 *
 */
bool threadexec_list_pids_with_paths(threadexec_t threadexec,
		pid_t **pids, char ***paths, size_t *count);

/*
 * threadexec_pids_for_path
 *
 * Description:
 * 	Get a list of all PIDs of processes running the specified executable.
 *
 * Parameters:
 * 	threadexec			The threadexec context.
 * 	path				The path of the main process executable to search for.
 * 	pids				An array to fill with the matching PIDs.
 * 	count				On entry, the length of the pids array. On return, the
 * 					true number of matching processes. If this value is larger
 * 					on return, then some entries were omitted from the array.
 *
 * Returns:
 * 	Returns true on success.
 */
bool threadexec_pids_for_path(threadexec_t threadexec, const char *path,
		pid_t *pids, size_t *count);

/*
 * threadexec_init_with_threadexec_and_pid
 *
 * Description:
 * 	Use one threadexec to create another threadexec for another process.
 *
 * Parameters:
 * 	threadexec			The privileged (task_for_pid, platform binary) threadexec
 * 					context.
 * 	pid				The PID of the process for which to create a new threadexec
 * 					context.
 *
 * Returns:
 * 	Returns a new threadexec context in the specified process on success and NULL on failure.
 *
 * Notes:
 * 	This routine exists because I can't figure out how to implement thread hijacking in
 * 	threadexec without corrupting the hijacked thread. Thus, we will use an existing threadexec
 * 	to create the thread safely, and then we will create the threadexec as usual.
 */
threadexec_t threadexec_init_with_threadexec_and_pid(threadexec_t threadexec, pid_t pid);

#endif
