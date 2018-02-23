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

#endif
