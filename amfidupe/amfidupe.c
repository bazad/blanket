#include <mach/mach.h>
#include <stdlib.h>
#include <unistd.h>

#include "amfidupe/process.h"

#include "blanket/log/log.h"

// The path to the amfid daemon.
const char *AMFID_PATH = "/usr/libexec/amfid";

// Get amfid's task port.
static mach_port_t
get_amfid_task() {
	// Get amfid's PID.
	pid_t amfid_pid;
	size_t count = 1;
	bool ok = proc_list_pids_with_path(AMFID_PATH, &amfid_pid, &count);
	if (!ok || count == 0) {
		ERROR("Could not find amfid process");
		return MACH_PORT_NULL;
	} else if (count > 1) {
		ERROR("Multiple processes with path %s", AMFID_PATH);
		return MACH_PORT_NULL;
	}
	DEBUG_TRACE(1, "Amfid PID: %d", amfid_pid);
	// Get amfid's task port.
	mach_port_t amfid_task;
	kern_return_t kr = task_for_pid(mach_task_self(), amfid_pid, &amfid_task);
	if (kr != KERN_SUCCESS) {
		ERROR("Could not get amfid task");
		return MACH_PORT_NULL;
	}
	return amfid_task;
}

int
main(int argc, const char *argv[]) {
	INFO("amfidupe: pid=%d, uid=%d", getpid(), getuid());
	mach_port_t amfid_task = get_amfid_task();
	if (amfid_task == MACH_PORT_NULL) {
		return 1;
	}
	INFO("Amfid task: 0x%x", amfid_task);
	return 0;
}
