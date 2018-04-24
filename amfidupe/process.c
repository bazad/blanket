#include "amfidupe/process.h"

#include <assert.h>
#include <string.h>
#include <sys/param.h>

// Prototypes from libproc.h.
extern int proc_listallpids(void *buffer, int buffersize);
extern int proc_pidpath(int pid, void *buffer, uint32_t buffersize);

bool
proc_list_pids_with_path(const char *path, pid_t *pids, size_t *count) {
	// Get the number of processes.
	int capacity = proc_listallpids(NULL, 0);
	if (capacity <= 0) {
		return false;
	}
	capacity += 10;
	assert(capacity > 0);
	// Get the list of all PIDs.
	pid_t all_pids[capacity];
	int all_count = proc_listallpids(all_pids, capacity * sizeof(*all_pids));
	if (all_count <= 0) {
		return false;
	}
	// Find all PIDs that match the specified path. We walk the list in reverse because
	// proc_listallpids seems to return the PIDs in reverse order.
	pid_t *end = pids + *count;
	size_t found = 0;
	for (int i = all_count - 1; i >= 0; i--) {
		pid_t pid = all_pids[i];
		// Get this process's path.
		char pid_path[MAXPATHLEN];
		int len = proc_pidpath(pid, pid_path, sizeof(pid_path));
		if (len <= 0) {
			continue;
		}
		// If it's a match, add it to the list and increment the number of PIDs found.
		if (strncmp(path, pid_path, len) == 0) {
			if (pids < end) {
				*pids = pid;
				pids++;
			}
			found++;
		}
	}
	*count = found;
	return true;
}
