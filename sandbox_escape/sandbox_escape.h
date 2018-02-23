#ifndef SANDBOX_ESCAPE__SANDBOX_ESCAPE_H_
#define SANDBOX_ESCAPE__SANDBOX_ESCAPE_H_

#include <stdbool.h>

/*
 * sandbox_escape
 *
 * Description:
 * 	Exploit the launchd-portrep vulnerability to escape the application sandbox and run code as
 * 	root with the task_for_pid-allow entitlement.
 */
bool sandbox_escape(void);

#endif
