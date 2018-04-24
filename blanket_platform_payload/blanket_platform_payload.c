#include <mach/mach.h>
#include <unistd.h>
#include <stdlib.h>

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

int
main(int argc, const char *argv[]) {
	pid_t blanket_pid;
	parse_arguments(argc, argv, &blanket_pid);
	INFO("blanket_platform_payload: pid=%d, uid=%d, blanket_pid=%d",
			getpid(), getuid(), blanket_pid);
	return 0;
}
