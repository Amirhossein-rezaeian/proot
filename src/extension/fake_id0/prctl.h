#ifndef FAKE_ID0_PRCTL_H
#define FAKE_ID0_PRCTL_H

#include "tracee/tracee.h"

extern int handle_prctl_sysexit_end(Tracee *tracee);
extern int handle_prctl_sysenter_end(Tracee *tracee);

#endif /* FAKE_ID0_PRCTL_H */
