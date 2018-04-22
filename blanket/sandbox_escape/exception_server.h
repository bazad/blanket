#ifndef BLANKET__SANDBOX_ESCAPE__EXCEPTION_SERVER_H_
#define BLANKET__SANDBOX_ESCAPE__EXCEPTION_SERVER_H_

#include <mach/mach.h>
#include <stdbool.h>

/*
 * catch_exception_block_t
 *
 * Description:
 * 	An exception block to be passed to exception_server_once().
 */
typedef bool (^catch_exception_block_t)(
		mach_port_t            thread,
		mach_port_t            task,
		exception_type_t       exception,
		exception_data_t       code,
		mach_msg_type_number_t codeCnt,
		kern_return_t *        result);

/*
 * catch_exception_server
 *
 * Description:
 * 	Run an exception server to listen for exception messages on the specified port. Any
 * 	non-exception messages will be destroyed. The exception server will run until the exception
 * 	block returns true.
 *
 * 	Only exception_raise() messages are supported.
 *
 * Parameters:
 * 	exception_port			The Mach port to listen on.
 * 	timeout_ns			The amount of time to listen for a new message before
 * 					giving up. Pass 0 for no timeout.
 * 	exception_block			A block to invoke when exception messages are received.
 * 					Once the block returns true, all further exception messages
 * 					on the port will be rejected and exception_server()
 * 					will return true. The result output variable is
 * 					KERN_SUCCESS by default.
 *
 * Returns:
 * 	Returns true if the block processed a message and returned true.
 *
 * Notes:
 * 	The port rights in the message are handled according to MIG semantics: if the exception
 * 	block sets result to a value other than KERN_SUCCESS, all resources will be deallocated,
 * 	otherwise if result is KERN_SUCCESS, no resources will be deallocated.
 */
bool catch_exception_server(mach_port_t exception_port, uint64_t timeout_ns,
		catch_exception_block_t exception_block);

#endif
