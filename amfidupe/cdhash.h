#ifndef BLANKET__AMFID__CDHASH_H_
#define BLANKET__AMFID__CDHASH_H_

#include <stdbool.h>
#include <stdlib.h>

#include "headers/cs_blobs.h"

/*
 * compute_cdhash
 *
 * Description:
 * 	Compute the cdhash of a Mach-O file.
 *
 * Parameters:
 * 	file				The contents of the Mach-O file.
 * 	size				The size of the Mach-O file.
 * 	cdhash			out	On return, contains the cdhash of the file. Must be
 * 					CS_CDHASH_LEN bytes.
 */
bool compute_cdhash(const void *file, size_t size, void *cdhash);

#endif
