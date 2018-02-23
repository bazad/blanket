#ifndef LAUNCHD_PORTREP_IOS__LAUNCHD_PORTREP_CRASHER_H_
#define LAUNCHD_PORTREP_IOS__LAUNCHD_PORTREP_CRASHER_H_

#include <mach/mach.h>
#include <stdbool.h>

/*
 * launchd_release_send_right_twice
 *
 * Description:
 * 	Cause launchd to release the specified send right twice by launching an app extension that
 * 	will crash. This should be enough to completely release launchd's send right for most of
 * 	the Mach services it vends.
 *
 * Parameters:
 * 	send_right			The Mach send right to try to force launchd to release.
 *
 * Returns:
 * 	Returns true on success.
 *
 * Implementation:
 * 	This function works by connecting to an application extension, launchd_portrep_crasher,
 * 	embededd in the main application bundle, and telling the extension process to crash in such
 * 	a way that the kernel sends a Mach exception message to launchd which deallocates the send
 * 	right.
 *
 * 	This implementation requires two specific features: application extensions and application
 * 	groups. The first allows us to create another process running our own code, so that when it
 * 	crashes we still have code execution. The second allows us to talk with that process and
 * 	register Mach ports in launchd. While it would be possible to work around these
 * 	requirements and eliminate the need for the application groups capability, the exploit is
 * 	much easier if we take advantage of these features.
 *
 * Notes:
 * 	This function cannot detect whether the send right was actually released; it will continue
 * 	to return true even when this vulnerability is patched.
 */
bool launchd_release_send_right_twice(mach_port_t send_right);

#endif
