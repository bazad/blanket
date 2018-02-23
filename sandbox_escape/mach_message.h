#ifndef SANDBOX_ESCAPE__MACH_MESSAGE_H_
#define SANDBOX_ESCAPE__MACH_MESSAGE_H_

#include <mach/mach.h>
#include <stdbool.h>

/*
 * mach_receive_message
 *
 * Description:
 * 	Receive a mach message on a port and pass it to the specified handler block. The message is
 * 	always received with an audit trailer.
 *
 * Parameters:
 * 	port				The Mach port on which to receive.
 * 	timeout_ms			The number of milliseconds to wait to receive a message.
 * 					Pass MACH_MSG_TIMEOUT_NONE for no timeout (wait
 * 					indefinitely).
 * 	handler				A handler block that is given the received message. The
 * 					handler block is responsible for processing the message and
 * 					taking ownership of any resources contained in it.
 *
 * Returns:
 * 	Returns true if the message was successfully sent.
 */
bool mach_receive_message(mach_port_t port, mach_msg_timeout_t timeout_ms,
		void (^handler)(mach_msg_header_t *msg));

/*
 * mach_send_message
 *
 * Description:
 * 	Send a Mach message.
 *
 * Parameters:
 * 	msg				The Mach message to send.
 *
 * Returns:
 * 	Returns true if the message was successfully sent.
 */
bool mach_send_message(mach_msg_header_t *msg);

/*
 * mach_mig_create_error
 *
 * Description:
 * 	Create a MIG error response for the given message. The reply struct should be zeroed
 * 	beforehand.
 *
 * Parameters:
 * 	request				The Mach message to which the reply is a reply.
 * 	reply				The reply structure to fill.
 * 	result				The result code to reply.
 */
void mach_mig_create_error(const mach_msg_header_t *request, mig_reply_error_t *reply,
		kern_return_t result);

/*
 * mach_message_get_pid
 *
 * Description:
 * 	Get the PID of the sender of a Mach message. The message must have been received with an
 * 	audit trailer.
 *
 * Parameters:
 * 	msg				The Mach message.
 *
 * Returns:
 * 	pid				The PID of the sender.
 */
int mach_message_get_pid(mach_msg_header_t *msg);

#endif
