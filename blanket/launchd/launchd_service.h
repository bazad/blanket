#ifndef BLANKET__LAUNCHD__LAUNCHD_SERVICE_H_
#define BLANKET__LAUNCHD__LAUNCHD_SERVICE_H_

#include <mach/mach.h>

/*
 * launchd_lookup_service
 *
 * Description:
 * 	Look up the send right to the specified service endpoint. This is a logging wrapper around
 * 	bootstrap_look_up().
 */
mach_port_t launchd_lookup_service(const char *endpoint);

#endif
