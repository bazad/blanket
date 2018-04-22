#include <mach/mach.h>

#include "headers/bootstrap.h"
#include "headers/mach_vm.h"

// Look up the bootstrap port so that we can communicate with launchd.
static mach_port_t
lookup_bootstrap_port() {
	// Retrieve the ports launchd registered using mach_ports_register().
	mach_port_t *init_ports;
	mach_msg_type_number_t init_port_count;
	kern_return_t kr = mach_ports_lookup(mach_task_self(), &init_ports, &init_port_count);
	if (kr != KERN_SUCCESS || init_port_count == 0) {
		return MACH_PORT_NULL;
	}
	// The first registered port is the bootstrap port.
	mach_port_t bootstrap = init_ports[0];
	// Deallocate the other ports.
	for (size_t i = 1; i < init_port_count; i++) {
		mach_port_deallocate(mach_task_self(), init_ports[i]);
	}
	// Deallocate the memory.
	mach_vm_deallocate(mach_task_self(), (mach_vm_address_t)init_ports,
			init_port_count * sizeof(*init_ports));
	// Return the bootstrap port.
	return bootstrap;
}

// Look up the bootstrap port during initialization. I'm not sure why this isn't happening
// automatically.
__attribute__((constructor))
static void
init_bootstrap_port() {
	bootstrap_port = lookup_bootstrap_port();
}
