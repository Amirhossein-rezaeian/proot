#ifndef FAKE_ID0_SHM_H
#define FAKE_ID0_SHM_H

#include <linux/shm.h>
#include <stdint.h>
#include <sys/types.h>

#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "extension/fake_id0/config.h"

#ifndef shmid_ds
# define shmid_ds shmid64_ds
#endif

extern int handle_shmget_sysenter_end(Tracee *tracee, RegVersion stage);
extern int handle_shmat_sysenter_end(Tracee *tracee, RegVersion stage);
extern int handle_shmat_sysexit_end(Tracee *tracee);
extern int handle_shmdt_sysenter_end(Tracee *tracee, RegVersion stage);
extern int handle_shmdt_sysexit_end(Tracee *tracee);
extern int handle_shmctl_sysenter_end(Tracee *tracee, RegVersion stage);

#endif /* FAKE_ID0_SHM_H */
