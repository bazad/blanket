#include <fcntl.h>
#include <libgen.h>
#include <mach/mach.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "blanket/log/log.h"

// Parse the program arguments.
static void
parse_arguments(int argc, const char *argv[], pid_t *blanket_pid) {
	if (argc != 2) {
		goto fail_usage;
	}
	char *end;
	pid_t pid = (pid_t) strtol(argv[1], &end, 0);
	if (*end != 0 || pid <= 0) {
		goto fail_usage;
	}
	*blanket_pid = pid;
	return;
fail_usage:
	ERROR("Usage: blanket_platform_payload <blanket_app_pid>");
	exit(1);
}

// Start the amfidupe daemon.
static bool
start_amfidupe(const char *self) {
	// Get the path to amfidupe.
	char directory[1024];
	dirname_r(self, directory);
	char amfidupe_path[1024];
	snprintf(amfidupe_path, sizeof(amfidupe_path), "%s/%s", directory, "amfidupe");
	DEBUG_TRACE(1, "amfidupe = \"%s\"", amfidupe_path);
	// Make amfidupe executable.
	int err = chmod(amfidupe_path, 0755);
	if (err != 0) {
		WARNING("Could not make amfidupe executable");
	}
	// Spawn amfidupe.
	pid_t amfidupe_pid;
	char *const amfidupe_argv[] = { amfidupe_path, NULL };
	char *const amfidupe_envp[] = { NULL };
	err = posix_spawn(&amfidupe_pid, amfidupe_path, NULL, NULL,
			amfidupe_argv, amfidupe_envp);
	if (err != 0) {
		ERROR("Could not spawn amfidupe: error %d", err);
		return false;
	}
	INFO("Spawned amfidupe as PID %d", amfidupe_pid);
	return true;
}

int
main(int argc, const char *argv[]) {
	pid_t blanket_pid;
	parse_arguments(argc, argv, &blanket_pid);
	INFO("blanket_platform_payload: pid=%d, uid=%d, blanket_pid=%d",
			getpid(), getuid(), blanket_pid);
	start_amfidupe(argv[0]);
	return 0;
}
