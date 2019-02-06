#include <linux/limits.h>
#include <string.h>
#include <unistd.h>

#include "extension/fake_id0/rename.h"
#include "extension/fake_id0/helper_functions.h"

/** Handles rename and renameat syscalls. 
 *  Check permissions of whether a rename is allowed. See rename(2) for
 *  returned permission errors.
 */
int handle_rename_enter_end(Tracee *tracee, Reg oldfd_sysarg, Reg oldpath_sysarg, 
	Reg newfd_sysarg, Reg newpath_sysarg, Config *config)
{
	int status;
	uid_t uid;
	gid_t gid;
	mode_t mode;
	char oldpath[PATH_MAX];

	status = read_sysarg_path(tracee, oldpath, oldpath_sysarg, CURRENT); 
	if(status < 0)
		return status;
	if(status == 1)
		return 0;

	//only read the meta info, so it can delete the meta file if it exists
	//TODO: Remove once there are no more meta files out there
	read_meta_info(oldpath, &mode, &uid, &gid, config);
	
	return 0;
}
