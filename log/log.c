#include "log/log.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

void
log_internal(char type, const char *format, ...) {
	if (log_implementation != NULL) {
		va_list ap;
		va_start(ap, format);
		log_implementation(type, format, ap);
		va_end(ap);
	}
}

// The default logging implementation simply prints to stderr.
static void
log_stderr(char type, const char *format, va_list ap) {
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
	fprintf(stderr, "%s%s%s\n", logtype, separator, message);
	free(message);
}

void (*log_implementation)(char type, const char *format, va_list ap) = log_stderr;
