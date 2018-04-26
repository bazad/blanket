#ifndef AMFIDUPE__AMFID_TYPES_H_
#define AMFIDUPE__AMFID_TYPES_H_

#include <stdint.h>

#include "headers/cs_blobs.h"

// C-equivalent types for amfid.mig.

typedef const char *amfid_path_t;
typedef const char *amfid_a13_t;
typedef uint8_t amfid_cdhash_t[CS_CDHASH_LEN];

#endif
