#include "blanket/log/log.h"

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

// We will log all output to this file.
static int blanket_platform_payload_logfd;

// The internal logging implementation for blanket_platform_payload. All log messages are written
// to the log file.
static void
blanket_platform_payload_log(char type, const char *format, va_list ap) {
	char *message = NULL;
	vasprintf(&message, format, ap);
	assert(message != NULL);
	const char *logtype   = "";
	const char *separator = ": ";
	switch (type) {
		case 'D': logtype = "Debug";   break;
		case 'I': logtype = "Info";    break;
		case 'W': logtype = "Warning"; break;
		case 'E': logtype = "Error";   break;
		default:  separator = "";
	}
	dprintf(blanket_platform_payload_logfd, "%s%s%s\n", logtype, separator, message);
	free(message);
}

// A constructor to initialize the logging system.
__attribute__((constructor))
static void
init_logging() {
	blanket_platform_payload_logfd = open("/var/root/blanket-log.txt",
			O_WRONLY | O_CREAT | O_TRUNC, 0644);
	assert(blanket_platform_payload_logfd >= 0);
	log_implementation = blanket_platform_payload_log;
}
