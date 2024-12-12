#include "extension/extension.h"
#include "tracee/mem.h"

static int handle_droid_files(Tracee *tracee)
{
    Sysnum sysnum = get_sysnum(tracee, ORIGINAL);
    switch (sysnum) {
    case PR_fopen: 
        return 0;

    default:
        return 0;
    }
}

/**
 * Handler for this @extension.  It is triggered each time an @event
 * occured.  See ExtensionEvent for the meaning of @data1 and @data2.
 */
int droid_files_callback(Extension *extension, ExtensionEvent event,
        intptr_t data1 UNUSED, intptr_t data2 UNUSED)
{
    switch (event) {
    case INITIALIZATION: {
        /* List of syscalls handled by this extension */
        static FilteredSysnum filtered_sysnums[] = {
            { PR_fopen,   0 },
            FILTERED_SYSNUM_END,
        };
        extension->filtered_sysnums = filtered_sysnums;
        return 0;
    }

    case SYSCALL_ENTER_END: {
        return handle_droid_files(TRACEE(extension));
    }

    default:
        return 0;
    }
}
