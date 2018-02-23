#ifndef SANDBOX_ESCAPE__MACH_SERVICE_MITM_H_
#define SANDBOX_ESCAPE__MACH_SERVICE_MITM_H_

#include <mach/mach.h>
#include <stdbool.h>

/*
 * mach_mitm_server_message_handler_t
 *
 * Description:
 * 	The type of a Mach message handler function. Return true to forward the message, false to
 * 	send a KERN_FAILURE reply.
 */
typedef bool (^mach_mitm_server_message_handler_t)(mach_msg_header_t *msg);

/*
 * mach_mitm_server_once
 *
 * Description:
 * 	Run the MITM server to process a single message.
 *
 * Parameters:
 * 	real_service			A send right to the real service.
 * 	fake_service			A receive right on the fake service port to which clients
 * 					will connect.
 * 	handle_message			A block to handle an incoming message.
 *
 * Returns:
 * 	True if one message was successfully handled.
 */
bool mach_mitm_server_once(mach_port_t real_service, mach_port_t fake_service,
		mach_mitm_server_message_handler_t handle_message);

/*
 * mach_mitm_server
 *
 * Description:
 * 	Run the MITM server in a loop until we encounter an error.
 *
 * Parameters:
 * 	real_service			A send right to the real service.
 * 	fake_service			A receive right on the fake service port to which clients
 * 					will connect.
 * 	handle_message			A block to handle an incoming message.
 */
void mach_mitm_server(mach_port_t real_service, mach_port_t fake_service,
		mach_mitm_server_message_handler_t handle_message);

/*
 * mach_message_inspect_ports
 *
 * Description:
 * 	Inspect all the Mach ports in a Mach message (except for msgh_local_port).
 *
 * Parameters:
 * 	msg				The message to inspect.
 * 	inspect_port			A callback block that will be given each valid port in the
 * 					message. Return true to stop iteration.
 */
void mach_message_inspect_ports(mach_msg_header_t *msg, bool (^inspect_port)(mach_port_t));

#endif
