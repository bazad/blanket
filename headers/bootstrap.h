#ifndef HEADERS__BOOTSTRAP_H_
#define HEADERS__BOOTSTRAP_H_

// Prototypes from bootstrap.h

#include <mach/mach.h>

extern mach_port_t bootstrap_port;

extern kern_return_t
bootstrap_register(mach_port_t bp, const char *service_name, mach_port_t sp);

extern kern_return_t
bootstrap_look_up(mach_port_t bp, const char *service_name, mach_port_t *sp);

#endif
