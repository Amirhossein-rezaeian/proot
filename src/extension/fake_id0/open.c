#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "tracee/reg.h"

#include "extension/fake_id0/open.h"
#include "extension/fake_id0/helper_functions.h"

/** Handles open, openat, and creat syscalls.
 *  Checks the permissions of files that already
 *  exist given matching meta info. See open(2) for returned permission
 *  errors.
 */
int handle_open_enter_end(Tracee *tracee, Reg fd_sysarg, Reg path_sysarg, 
	Reg flags_sysarg, Reg mode_sysarg, Config *config)
{   
	int status, perms, access_mode;
	char orig_path[PATH_MAX];
	word_t flags;
	mode_t mode;

	status = read_sysarg_path(tracee, orig_path, path_sysarg, CURRENT);
	if(status < 0) 
		return status;
	if(status == 1) 
		return 0;

	if(path_exists(orig_path) == 0) 
		tracee->already_exists = true;
	else
		tracee->already_exists = false;

	if(flags_sysarg != IGNORE_SYSARG) 
		flags = peek_reg(tracee, ORIGINAL, flags_sysarg);
	else  
		flags = O_CREAT;

	/* If the file doesn't exist and we aren't creating a new file, get out. */
	if(path_exists(orig_path) != 0 && (flags & O_CREAT) != O_CREAT) 
		return 0;

	if((flags & O_CREAT) == O_CREAT) { 
		if(path_exists(orig_path) == 0) 
			goto check;

		mode = peek_reg(tracee, ORIGINAL, mode_sysarg);
		poke_reg(tracee, mode_sysarg, (mode|0700));
		return 0;
	}

check:
	
        perms = get_permissions(orig_path, config, 0);
	access_mode = (flags & O_ACCMODE);

	/* 0 = RDONLY, 1 = WRONLY, 2 = RDWR */
	if((access_mode == O_WRONLY && (perms & 2) != 2) ||
	(access_mode == O_RDONLY && (perms & 4) != 4) ||
	(access_mode == O_RDWR && (perms & 6) != 6)) {
		return -EACCES;
	}

	return 0;
}

/** Handles open, openat, and creat syscalls. Creates meta info to match the
 *  creation of new files.
 */
int handle_open_exit_end(Tracee *tracee, Reg path_sysarg, 
	Reg flags_sysarg, Reg mode_sysarg, Config *config)
{   
	int status;
	char orig_path[PATH_MAX];
	word_t flags;
	mode_t mode;
	word_t result;

	//only matters if it succeeded 
	result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if (result & ((word_t)1 << (sizeof(word_t)*8 - 1)))
		return 0;

	status = read_sysarg_path(tracee, orig_path, path_sysarg, MODIFIED);
	if(status < 0) 
		return status;
	if(status == 1) 
		return 0;

	if(flags_sysarg != IGNORE_SYSARG) 
		flags = peek_reg(tracee, ORIGINAL, flags_sysarg);
	else  
		flags = O_CREAT;

	/* If the file already existed or we aren't creating a new file, get out. */
	if(tracee->already_exists || ((flags & O_CREAT) != O_CREAT)) 
		return 0;

	mode = peek_reg(tracee, ORIGINAL, mode_sysarg);
	return write_meta_info(orig_path, mode, config->euid, config->egid, 1, config);
}

