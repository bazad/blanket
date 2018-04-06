#ifndef SANDBOX_ESCAPE__SANDBOX_ESCAPE_H_
#define SANDBOX_ESCAPE__SANDBOX_ESCAPE_H_

#include "threadexec/threadexec.h"

/*
 * sandbox_escape
 *
 * Description:
 * 	Exploit the launchd-portrep vulnerability to escape the application sandbox and run code as
 * 	root with the task_for_pid-allow entitlement.
 *
 * Returns:
 * 	If successful, returns an execution context in the ReportCrash process, which can be used
 * 	to execute arbitrary code. ReportCrash is unsandboxed, runs as root, and has the
 * 	task_for_pid-allow entitlement.
 */
threadexec_t sandbox_escape(void);

#endif
