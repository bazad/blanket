#ifndef BLANKET__XPC_CRASH__XPC_CRASH_H_
#define BLANKET__XPC_CRASH__XPC_CRASH_H_

#include <stdbool.h>

/*
 * xpc_crash
 *
 * Description:
 * 	Crash the specified XPC service.
 *
 * Parameters:
 * 	service				The name of the service endpoint.
 *
 * Returns:
 * 	Returns true if the service appears to have crashed.
 */
bool xpc_crash(const char *service);

#endif
