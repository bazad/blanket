#ifndef BLANKET__DRUID__DRUID_H_
#define BLANKET__DRUID__DRUID_H_

#include <stdbool.h>

/*
 * druid_start
 *
 * Description:
 * 	Ensure that the the druid (Drag UI) daemon is up and running.
 *
 * Returns:
 * 	Returns true if successful.
 */
bool druid_start(void);

/*
 * druid_crash
 *
 * Description:
 * 	Send a message to try and crash the druid daemon.
 *
 * Returns:
 * 	Returns true if the druid daemon appears to have crashed.
 */
bool druid_crash(void);

#endif
