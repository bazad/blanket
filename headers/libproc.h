#ifndef HEADERS__LIBPROC_H_
#define HEADERS__LIBPROC_H_

// Prototypes from libproc.h

extern int proc_listallpids(void *buffer, int buffersize);

extern int proc_pidpath(int pid, void *buffer, uint32_t buffersize);

#endif
