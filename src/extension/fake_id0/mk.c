#include <linux/limits.h>

#include "extension/fake_id0/mk.h"

#include "extension/fake_id0/helper_functions.h"

/** Handles mkdir, mkdirat, mknod, and mknodat syscalls. Creates matching
 *  meta info. See mkdir(2) and mknod(2) for returned permission errors.
 */
int handle_mk_enter_end(Tracee *tracee, Reg fd_sysarg, Reg path_sysarg, 
	Reg mode_sysarg, Config *config)
{
	int status;
	mode_t mode;
	char orig_path[PATH_MAX];

	status  = read_sysarg_path(tracee, orig_path, path_sysarg, CURRENT);
	if(status < 0)
		return status;
	if(status == 1)
		return 0;

	/* If the path exists, get out. The syscall itself will return EEXIST. */
	if(path_exists(orig_path)) {
		tracee->already_exists = true;
	} else {
		tracee->already_exists = false;
		return 0;
	}

	mode = peek_reg(tracee, ORIGINAL, mode_sysarg);
	poke_reg(tracee, mode_sysarg, (mode|0700));
	return 0;
}

/** Handles mkdir, mkdirat, mknod, and mknodat syscalls. Creates matching
 *  meta info. See mkdir(2) and mknod(2) for returned permission errors.
 */
int handle_mk_exit_end(Tracee *tracee, Reg path_sysarg, 
	Reg mode_sysarg, Config *config)
{
	int status;
	mode_t mode;
	char orig_path[PATH_MAX];
	word_t result;

	//only matters if it succeeded 
	result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if (result != 0) 
		return 0;

	status  = read_sysarg_path(tracee, orig_path, path_sysarg, CURRENT);
	if(status < 0)
		return status;
	if(status == 1)
		return 0;

	/* If the file already existed get out*/
	if(tracee->already_exists)
		return 0;

	mode = peek_reg(tracee, ORIGINAL, mode_sysarg);
	poke_reg(tracee, mode_sysarg, (mode|0700));
	return write_meta_info(orig_path, mode, config->euid, config->egid, 1, config);
}
