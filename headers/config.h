#ifndef HEADERS__CONFIG_H_
#define HEADERS__CONFIG_H_

// The application group configured in Xcode.
#define APP_GROUP	"group.com.github.bazad.test"

// The name of the payload binary.
#define PAYLOAD_NAME	"blanket_payload"

// The root directory of binaries for the payload.
#define PAYLOAD_BINPACK_DIRECTORY	"binpack"

// The name of the launchd_portrep_crasher app extension. This string gets appended to the main
// app's bundle identifier to get the extension's bundle identifier.
#define LAUNCHD_PORTREP_CRASHER_NAME	"launchd-portrep-crasher"

// How many ports to use in the port replacement exploit.
#define PORT_REUSE_COUNT	(500)
#define PORT_FREELIST_COUNT	(PORT_REUSE_COUNT / 2)

#endif
