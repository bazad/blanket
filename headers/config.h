#ifndef HEADERS__CONFIG_H_
#define HEADERS__CONFIG_H_

// The application group configured in Xcode.
#define APP_GROUP "group.com.github.bazad.test"

// How many ports to use in the port replacement exploit.
#define PORT_REUSE_COUNT	(500)
#define PORT_FREELIST_COUNT	(PORT_REUSE_COUNT / 2)

#endif
