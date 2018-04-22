#include <mach/mach.h>
#include <unistd.h>

#include "blanket/log/log.h"
#include "headers/mach_vm.h"

int main(int argc, const char *argv[]) {
	INFO("blanket_platform_payload: pid=%d, uid=%d, euid=%d", getpid(), getuid(), geteuid());
	mach_port_t launchd_task = MACH_PORT_NULL;
	kern_return_t kr = task_for_pid(mach_task_self(), 1, &launchd_task);
	INFO("task_for_pid(1): kr = %u, task = 0x%x", kr, launchd_task);
	mach_vm_address_t address = 0;
	mach_vm_size_t size = 0x8000;
	kr = mach_vm_allocate(launchd_task, &address, size, VM_FLAGS_ANYWHERE);
	INFO("mach_vm_allocate(0x%x, 0x%llx): kr = %u, address = %p",
			launchd_task, size, kr, (void *)address);
	return 0;
}
