#ifndef BLANKET__SANDBOX_ESCAPE__SPAWN_PRIVILEGED_H_
#define BLANKET__SANDBOX_ESCAPE__SPAWN_PRIVILEGED_H_

#include "threadexec/threadexec.h"

/*
 * spawn_privileged
 *
 * Description:
 * 	Use a privileged execution context to spawn a process.
 *
 * Parameters:
 * 	priv_tx				A threadexec execution context in an unsandboxed, root, and
 * 					task_for_pid process.
 * 	path				The path to the executable to spawn. The executable does
 * 					not need to have execute permission set.
 * 	argv				The arguments array. May be NULL to use a default value of
 * 					just the path.
 * 	envp				The environment array. May be NULL to specify no
 * 					environment.
 * 	stdio_fds			An array of 3 file descriptors to use as stdin, stdout, and
 * 					stderr in the spawned process. May be NULL.
 *
 * Returns:
 * 	Returns the PID of the spawned process or -1.
 */
pid_t spawn_privileged(threadexec_t priv_tx, const char *path,
		const char **argv, const char **envp,
		const int *stdio_fds);

#endif
