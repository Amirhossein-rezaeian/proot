#ifndef FAKE_ID0_SEM_H
#define FAKE_ID0_SEM_H

#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "extension/fake_id0/config.h"

extern int handle_semget_sysexit_end(Tracee *tracee, RegVersion stage);
extern int handle_semctl_sysexit_end(Tracee *tracee, RegVersion stage);
extern int handle_semop_sysexit_end(Tracee *tracee, RegVersion stage);

#endif /* FAKE_ID0_SEM_H */
