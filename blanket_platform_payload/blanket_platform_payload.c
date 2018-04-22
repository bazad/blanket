#include <mach/mach.h>
#include <unistd.h>

#include "blanket/log/log.h"

int main(int argc, const char *argv[]) {
	INFO("blanket_platform_payload: pid=%d, uid=%d", getpid(), getuid());
	return 0;
}
