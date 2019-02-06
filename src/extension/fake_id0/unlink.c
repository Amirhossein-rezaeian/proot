#include <linux/limits.h>
#include <unistd.h>

#include "extension/fake_id0/unlink.h"
#include "extension/fake_id0/helper_functions.h"

/** Handles unlink, unlinkat, and rmdir syscalls. Checks permissions in meta 
 *  files matching the file to be unlinked if meta info exists. Deletes
 *  the meta info if the call would be successful. See unlink(2) and rmdir(2)
 *  for returned errors.
 */
int handle_unlink_enter_end(Tracee *tracee, Reg fd_sysarg, Reg path_sysarg, Config *config)
{
	int status;
	char orig_path[PATH_MAX];

	status = read_sysarg_path(tracee, orig_path, path_sysarg, CURRENT); 
	if(status < 0) 
		return status;
	if(status == 1)
		return 0;

	delete_meta_info(orig_path);

	return 0;
}
