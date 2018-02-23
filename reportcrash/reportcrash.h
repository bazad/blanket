#ifndef REPORTCRASH__REPORTCRASH_H_
#define REPORTCRASH__REPORTCRASH_H_

#include <mach/mach.h>
#include <stdbool.h>

/*
 * REPORTCRASH_SERVICE_NAME
 *
 * Description:
 * 	The name of the ReportCrash service endpoint in launchd.
 */
extern const char REPORTCRASH_SERVICE_NAME[];

/*
 * REPORTCRASH_SAFETYNET_SERVICE_NAME
 *
 * Description:
 * 	The name of the ReportCrash SafetyNet service endpoint in launchd.
 */
extern const char REPORTCRASH_SAFETYNET_SERVICE_NAME[];

/*
 * reportcrash_kickstart
 *
 * Description:
 * 	Ensure that the specified ReportCrash service is running.
 *
 * Parameters:
 * 	reportcrash_service		The ReportCrash service instance to kickstart.
 * 	pid			out	On return, contains the PID of the ReportCrash instance.
 * 					May be NULL.
 *
 * Returns:
 * 	Returns true if the service was successfully started.
 */
bool reportcrash_kickstart(mach_port_t reportcrash_service, pid_t *pid);

/*
 * reportcrash_keepalive_assertion_t
 *
 * Description:
 * 	The type of block returned by reportcrash_keepalive.
 */
typedef uintptr_t reportcrash_keepalive_assertion_t;

/*
 * reportcrash_keepalive
 *
 * Description:
 * 	Create an assertion that will keep the specified ReportCrash service alive. If the service
 * 	is not already running it will be started.
 *
 * Parameters:
 * 	reportcrash_service		The ReportCrash service instance to keep alive.
 *
 * Returns:
 * 	Returns a keepalive assertion on success and 0 on failure.
 *
 * Notes:
 * 	This function does not check that the ReportCrash service was actually started.
 */
reportcrash_keepalive_assertion_t reportcrash_keepalive(mach_port_t reportcrash_service);

/*
 * reportcrash_keepalive_assertion_release
 *
 * Description:
 * 	Release a keepalive assertion created by reportcrash_keepalive(). This will crash the
 * 	ReportCrash service with EXC_BAD_ACCESS.
 *
 * Parameters:
 * 	assertion			A keepalive assertion created by reportcrash_keepalive().
 */
void reportcrash_keepalive_assertion_release(reportcrash_keepalive_assertion_t assertion);

/*
 * reportcrash_exit
 *
 * Description:
 * 	Cause the specified ReportCrash service to exit.
 *
 * Parameters:
 * 	reportcrash_service		The ReportCrash service instance to exit.
 *
 * Returns:
 * 	Returns true if the exit has been triggered. ReportCrash may continue running for some time
 * 	after this, but will not process more Mach messages. The service port will remain valid,
 * 	and messages delivered to it will be processed by the next ReportCrash instance.
 */
bool reportcrash_exit(mach_port_t reportcrash_service);

/*
 * reportcrash_crash
 *
 * Description:
 * 	Crash the specified ReportCrash service with EXC_BAD_ACCESS.
 *
 * Parameters:
 * 	reportcrash_service		The ReportCrash service instance to crash.
 * 	wait				If true, then this function will wait for a reply
 * 					indicating that the crash was successful.
 *
 * Returns:
 * 	Returns true if ReportCrash appears to have been crashed.
 */
bool reportcrash_crash(mach_port_t reportcrash_service, bool wait);

#endif
