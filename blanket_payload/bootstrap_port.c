/*
 * bootstrap_port.c
 * Brandon Azad
 *
 * When spawning a process on iOS 11 by calling posix_spawn() in launchd, the bootstrap state does
 * not get initialized properly. Including this file will re-initialize the bootstrap state so that
 * interaction with launchd works as expected.
 *
 */

#include <mach/mach.h>

// Definitions and prototypes for XPC.
typedef void *xpc_pipe_t;
extern xpc_pipe_t xpc_pipe_create_from_port(mach_port_t port, uint32_t flags);
extern void xpc_release(void *);

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
	vm_deallocate(mach_task_self(), (vm_address_t)init_ports,
			init_port_count * sizeof(*init_ports));
	// Return the bootstrap port.
	return bootstrap;
}

// Set up our new bootstrap port.
static void
setup_bootstrap_port() {
	task_set_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, bootstrap_port);
}

// Initialize the XPC bootstrap pipe.
static void
setup_xpc_bootstrap_pipe() {
	struct _os_alloc_once_s {
		long once;
		void *ptr;
	};
	extern struct _os_alloc_once_s _os_alloc_once_table[];
	struct xpc_global_data {
		uint64_t a;
		uint64_t xpc_flags;
		mach_port_t task_bootstrap_port;
		xpc_pipe_t xpc_bootstrap_pipe;
	};
	struct xpc_global_data *xpc_global_data = _os_alloc_once_table[1].ptr;
	xpc_global_data->task_bootstrap_port = bootstrap_port;
	xpc_pipe_t old_pipe = xpc_global_data->xpc_bootstrap_pipe;
	xpc_global_data->xpc_bootstrap_pipe = xpc_pipe_create_from_port(bootstrap_port, 0);
	xpc_release(old_pipe);
}

// Initialize the bootstrap port and create a new XPC bootstrap pipe during initialization. This
// happens automatically for processes that launchd spawns the normal way.
__attribute__((constructor))
static void
init_bootstrap_port() {
	if (bootstrap_port == MACH_PORT_NULL) {
		bootstrap_port = lookup_bootstrap_port();
		setup_bootstrap_port();
		setup_xpc_bootstrap_pipe();
	}
}
