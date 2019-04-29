#ifndef _SYS_SHM_H
#define _SYS_SHM_H

#include <linux/shm.h>
#include <stdint.h>
#include <sys/types.h>

__BEGIN_DECLS

#ifndef shmid_ds
# define shmid_ds shmid64_ds
#endif

__END_DECLS

#endif
