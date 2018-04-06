#include "main/blanket_main.h"

#include "log/log.h"
#include "sandbox_escape/sandbox_escape.h"

#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>

void
blanket_main() {
	DEBUG_TRACE(1, "%s", __func__);
	threadexec_t reportcrash_tx = sandbox_escape();
	sleep(20);
	threadexec_deinit(reportcrash_tx);
	DEBUG_TRACE(1, "%s: done", __func__);
	exit(1);
}
