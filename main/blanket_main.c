#include "main/blanket_main.h"

#include "log/log.h"
#include "sandbox_escape/sandbox_escape.h"

#include <stdlib.h>

void
blanket_main() {
	DEBUG_TRACE(1, "%s", __func__);
	sandbox_escape();
	DEBUG_TRACE(1, "%s: Done", __func__);
	exit(1);
}
