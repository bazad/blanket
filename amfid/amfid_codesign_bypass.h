#ifndef AMFID__AMFID_CODESIGN_BYPASS_H_
#define AMFID__AMFID_CODESIGN_BYPASS_H_

#include "threadexec/threadexec.h"

/*
 * amfid_codesign_bypass_install
 *
 * Description:
 * 	Install Ian Beer's codesigning bypass in amfid.
 */
bool amfid_codesign_bypass_install(threadexec_t priv_tx);

/*
 * amfid_codesign_bypass_remove
 *
 * Description:
 * 	Remove the codesigning bypass from amfid and allow amfid to run uninhibited.
 */
void amfid_codesign_bypass_remove(void);

#endif
