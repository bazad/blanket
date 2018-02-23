#include "launchd/launchd_service.h"

#include "headers/bootstrap.h"
#include "log/log.h"

mach_port_t
launchd_lookup_service(const char *endpoint) {
	mach_port_t service_port = MACH_PORT_NULL;
	kern_return_t kr = bootstrap_look_up(bootstrap_port, endpoint, &service_port);
	if (kr != KERN_SUCCESS) {
		ERROR("%s(%s): %u", "bootstrap_look_up", endpoint, kr);
		return MACH_PORT_NULL;
	}
	if (!MACH_PORT_VALID(service_port)) {
		ERROR("%s(%s): %s", "bootstrap_look_up", endpoint,
				(service_port == MACH_PORT_NULL
				 ? "MACH_PORT_NULL" : "MACH_PORT_DEAD"));
		return MACH_PORT_NULL;
	}
	return service_port;
}
