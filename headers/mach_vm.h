#ifndef HEADERS__MACH_VM_H_
#define HEADERS__MACH_VM_H_

// Prototypes from mach/mach_vm.h

#include <mach/mach.h>

extern
kern_return_t mach_vm_allocate
(
	vm_map_t target,
	mach_vm_address_t *address,
	mach_vm_size_t size,
	int flags
);

extern
kern_return_t mach_vm_deallocate
(
	vm_map_t target,
	mach_vm_address_t address,
	mach_vm_size_t size
);

extern
kern_return_t mach_vm_region
(
	vm_map_t target_task,
	mach_vm_address_t *address,
	mach_vm_size_t *size,
	vm_region_flavor_t flavor,
	vm_region_info_t info,
	mach_msg_type_number_t *infoCnt,
	mach_port_t *object_name
);

#endif
