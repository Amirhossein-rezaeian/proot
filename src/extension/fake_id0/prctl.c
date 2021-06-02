#include <sys/prctl.h>

#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "tracee/mem.h"
#include "extension/extension.h"
#include "extension/fake_id0/prctl.h"

int handle_prctl_sysexit_end(Tracee *tracee)
{
	int option = (int)peek_reg(tracee, ORIGINAL, SYSARG_1);
	if (option == PR_SET_DUMPABLE)
		poke_reg(tracee, SYSARG_RESULT, (word_t)0);
	return 0;
}

int handle_prctl_sysenter_end(Tracee *tracee)
{
	int option = (int)peek_reg(tracee, ORIGINAL, SYSARG_1);
	if (option == PR_SET_DUMPABLE)
		set_sysnum(tracee, PR_getuid);
	return 0;
}
