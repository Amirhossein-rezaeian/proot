#include <errno.h>
#include <linux/limits.h>

#include "syscall/sysnum.h"
#include "extension/fake_id0/chmod.h"

#include "extension/fake_id0/helper_functions.h"

/** Handles chmod, fchmod, and fchmodat syscalls. Changes meta info to the new
 *  permissions if the meta info exists. See chmod(2) for returned permission
 *  errors. 
 */
int handle_chmod_enter_end(Tracee *tracee, Reg path_sysarg, Reg mode_sysarg, 
	Reg fd_sysarg, Reg dirfd_sysarg, Config *config)
{
	int status;
	mode_t call_mode, read_mode;
	uid_t owner;
	gid_t group;
	char path[PATH_MAX];

	// When path_sysarg is set to IGNORE, the call being handled is fchmod.
	if(path_sysarg == IGNORE_SYSARG) 
		status = get_fd_path(tracee, path, fd_sysarg, CURRENT);
	else
		status = read_sysarg_path(tracee, path, path_sysarg, CURRENT);
	if(status < 0)
		return status;
	// If the file exists outside the guestfs, drop the syscall.
	else if(status == 1) {
		set_sysnum(tracee, PR_getuid);
		return 0;
	}

	read_meta_info(path, &read_mode, &owner, &group, config);
	if(config->euid != owner && config->euid != 0) 
		return -EPERM;

	call_mode = peek_reg(tracee, ORIGINAL, mode_sysarg);
	set_sysnum(tracee, PR_getuid);
	return write_meta_info(path, call_mode, owner, group, 0, config);
}
