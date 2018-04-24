#ifndef AMFIDUPE__FIND_PROCESS_H_
#define AMFIDUPE__FIND_PROCESS_H_

#include <stdbool.h>
#include <stdlib.h>

/*
 * proc_list_pids_with_path
 *
 * Description:
 * 	Find the PIDs of all processes with the given path.
 *
 * Parameters:
 * 	path				The canonical path to search for.
 * 	pids			out	On return, the array is filled with the PIDs of the
 * 					matching processes. May be NULL.
 * 	count			inout	On entry, the capacity of the pids array. On return, the
 * 					number of matching PIDs found. If this is greater than the
 * 					count on entry, then not all PIDs were stored in the array.
 *
 * Returns:
 * 	True if no errors were encountered.
 */
bool proc_list_pids_with_path(const char *path, pid_t *pids, size_t *count);

#endif
