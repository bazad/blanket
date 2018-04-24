#include <mach/mach.h>
#include <stdlib.h>
#include <unistd.h>

#include "blanket/log/log.h"

int
main(int argc, const char *argv[]) {
	INFO("amfidupe: pid=%d, uid=%d", getpid(), getuid());
	return 0;
}
