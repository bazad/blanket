#ifndef BLANKET__AMFID__AMFID_CODESIGN_BYPASS_H_
#define BLANKET__AMFID__AMFID_CODESIGN_BYPASS_H_

#include "threadexec/threadexec.h"

/*
 * amfid_codesign_bypass_install
 *
 * Description:
 * 	Install Ian Beer's codesigning bypass in amfid. Also mark binaries validated by amfid as
 * 	platform binaries, giving them the ability to manipulate task ports of other platform
 * 	binaries.
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
