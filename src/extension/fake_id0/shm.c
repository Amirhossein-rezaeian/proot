#include <android/log.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <paths.h>
#include <linux/limits.h>

#define __u32 uint32_t
#include <linux/ashmem.h>

#include "extension/extension.h"
#include "cli/note.h"
#include "tracee/mem.h"
#include "path/path.h"

#include "extension/fake_id0/shm.h"

#define ROUND_UP(N, S) ((((N) + (S) - 1) / (S)) * (S))

typedef struct {
	int id;
	void *addr;
	int descriptor;
	size_t size;
	bool markedForDeletion;
	key_t key;
} shmem_t;

static shmem_t* shmem = NULL;
static size_t shmem_amount = 0;

/*
 * From https://android.googlesource.com/platform/system/core/+/master/libcutils/ashmem-dev.c
 *
 * ashmem_create_region - creates a new named ashmem region and returns the file
 * descriptor, or <0 on error.
 *
 * `name' is the label to give the region (visible in /proc/pid/maps)
 * `size' is the size of the region, in page-aligned bytes
 */
static int ashmem_create_region(char const* name, size_t size)
{
	int fd = open("/dev/ashmem", O_RDWR);
	if (fd < 0) return fd;

	char name_buffer[ASHMEM_NAME_LEN] = {0};
	strncpy(name_buffer, name, sizeof(name_buffer));
	name_buffer[sizeof(name_buffer)-1] = 0;

	int ret = ioctl(fd, ASHMEM_SET_NAME, name_buffer);
	if (ret < 0) goto error;

	ret = ioctl(fd, ASHMEM_SET_SIZE, size);
	if (ret < 0) goto error;

	return fd;
error:
	close(fd);
	return ret;
}

static void android_shmem_delete(int idx)
{
	if (shmem[idx].descriptor) close(shmem[idx].descriptor);
	shmem_amount--;
	memmove(&shmem[idx], &shmem[idx+1], (shmem_amount - idx) * sizeof(shmem_t));
}

static int ashv_find_index(int shmid)
{
	for (size_t i = 0; i < shmem_amount; i++)
		if (shmem[i].id == shmid)
			return i;
	return -1;
}

static int ashv_find_key(key_t key)
{
	for (size_t i = 0; i < shmem_amount; i++)
		if (shmem[i].key == key)
			return i;
	return -1;
}

static int ashv_find_descriptor(int descriptor)
{
	for (size_t i = 0; i < shmem_amount; i++)
		if (shmem[i].descriptor == descriptor)
			return i;
	return -1;
}

static int ashv_find_addr(void *addr)
{
	for (size_t i = 0; i < shmem_amount; i++)
		if (shmem[i].addr == addr)
			return i;
	return -1;
}

/* Get shared memory area identifier. */
int handle_shmget_sysenter_end(Tracee *tracee, RegVersion stage)
{
	static size_t shmem_counter = 0;
	int shmid = -1;
	key_t key = (key_t)peek_reg(tracee, stage, SYSARG_1);
	size_t size = (size_t)peek_reg(tracee, stage, SYSARG_2);

	if (key != IPC_PRIVATE) {
		int key_idx = ashv_find_key(key);
		if (key_idx != -1) {
			poke_reg(tracee, SYSARG_RESULT, (word_t)shmem[key_idx].id);
			return 0;
		}
	}

	int idx = shmem_amount;
	char buf[256];
	sprintf(buf, "proot-%d", idx);

	shmem_amount++;
	if (shmid == -1) {
		shmem_counter = shmem_counter + 1;
		shmid = shmem_counter;
	}

	shmem = realloc(shmem, shmem_amount * sizeof(shmem_t));
	size = ROUND_UP(size, getpagesize());
	shmem[idx].size = size;
	shmem[idx].descriptor = ashmem_create_region(buf, size);
	shmem[idx].addr = NULL;
	shmem[idx].id = shmid;
	shmem[idx].markedForDeletion = false;
	shmem[idx].key = key;

	if (shmem[idx].descriptor < 0) {
		VERBOSE(tracee, 4, "%s: ashmem_create_region() failed for size %zu: %s", __PRETTY_FUNCTION__, size, strerror(errno));
		shmem_amount --;
		shmem = realloc(shmem, shmem_amount * sizeof(shmem_t));
		poke_reg(tracee, SYSARG_RESULT, (word_t)-1);
		return 0;
	}

	poke_reg(tracee, SYSARG_RESULT, (word_t)shmid);
	return 0;
}

/* Attach shared memory segment. */
int handle_shmat_sysenter_end(Tracee *tracee, RegVersion stage)
{
	int shmid = (int)peek_reg(tracee, stage, SYSARG_1);
	void *shmaddr = (void *)peek_reg(tracee, stage, SYSARG_2);
	int shmflg = (int)peek_reg(tracee, stage, SYSARG_3);
	int idx = ashv_find_index(shmid);
	if (idx == -1) {
		VERBOSE(tracee, 4, "%s: shmid %x does not exist", __PRETTY_FUNCTION__, shmid);
		return -EINVAL;
	}
	if (shmem[idx].addr == NULL) {
		set_sysnum(tracee, PR_mmap);
		poke_reg(tracee, SYSARG_1, (word_t)shmaddr);
		poke_reg(tracee, SYSARG_2, (word_t)shmem[idx].size);
		poke_reg(tracee, SYSARG_3, (word_t)(PROT_READ | (shmflg == 0 ? PROT_WRITE : 0)));
		poke_reg(tracee, SYSARG_4, (word_t)MAP_SHARED);
		poke_reg(tracee, SYSARG_5, (word_t)shmem[idx].descriptor);
		poke_reg(tracee, SYSARG_6, (word_t)0);
	} else {
		set_sysnum(tracee, PR_getuid);
	}

	return 0;
}

/* Attach shared memory segment. */
int handle_shmat_sysexit_end(Tracee *tracee)
{
	word_t sysnum;
	word_t result;
	int fd;
	int idx; 
	void *addr;
	int shmid;

	sysnum = get_sysnum(tracee, CURRENT);
	switch (sysnum) {
	case PR_mmap:
		fd = (int)peek_reg(tracee, MODIFIED, SYSARG_5);
		idx = ashv_find_descriptor(fd);
		if (idx == -1) {
			VERBOSE(tracee, 4, "%s: fd %d does not exist", __PRETTY_FUNCTION__, fd);
			return -EINVAL;
		}
		result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
		if ((int)result < 0) {
			VERBOSE(tracee, 4, "%s: mmap() failed for ID %x FD %d: %s", __PRETTY_FUNCTION__, idx, fd, strerror(-1*(int)result));
			shmem[idx].addr = NULL;
		} else {
			shmem[idx].addr = (void*)result;
		}
		break;
	case PR_getuid:
		shmid = (int)peek_reg(tracee, MODIFIED, SYSARG_1);
		idx = ashv_find_index(shmid);
	default:
		return 0;
	}

	addr = shmem[idx].addr;
	VERBOSE(tracee, 4, "%s: mapped addr %p for FD %d ID %d", __PRETTY_FUNCTION__, addr, shmem[idx].descriptor, idx);
	poke_reg(tracee, SYSARG_RESULT, (word_t)(addr ? addr : (void *)-1));

	return 0;
}

/* Detach shared memory segment. */
int handle_shmdt_sysenter_end(Tracee *tracee, RegVersion stage)
{
	void *shmaddr = (void *)peek_reg(tracee, stage, SYSARG_1);
	int idx = ashv_find_addr(shmaddr);
	if (idx == -1) {
		VERBOSE(tracee, 4, "%s: invalid address %p", __PRETTY_FUNCTION__, shmaddr);
		/* Could be a removed segment, do not report an error for that. */
		set_sysnum(tracee, PR_getuid);
	} else {
		set_sysnum(tracee, PR_munmap);
		poke_reg(tracee, SYSARG_1, (word_t)shmem[idx].addr);
		poke_reg(tracee, SYSARG_2, (word_t)shmem[idx].size);
	}

	return 0;
}

/* Detach shared memory segment. */
int handle_shmdt_sysexit_end(Tracee *tracee)
{
	word_t sysnum;
	word_t result;
	void *shmaddr;
	int idx;

	sysnum = get_sysnum(tracee, CURRENT);
	if (sysnum != PR_munmap) {
		poke_reg(tracee, SYSARG_RESULT, (word_t)0);
		return 0;
	}

	shmaddr = (void *)peek_reg(tracee, MODIFIED, SYSARG_1);
	idx = ashv_find_addr(shmaddr);
	if (idx == -1) {
		VERBOSE(tracee, 4, "%s: invalid address %p", __PRETTY_FUNCTION__, shmaddr);
		/* Could be a removed segment, do not report an error for that. */
		poke_reg(tracee, SYSARG_RESULT, (word_t)0);
		return 0;
	}
	result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if (result != 0) {
		VERBOSE(tracee, 4, "%s: munmap %p failed", __PRETTY_FUNCTION__, shmaddr);
		poke_reg(tracee, SYSARG_RESULT, (word_t)0);
	}
	shmem[idx].addr = NULL;
	VERBOSE(tracee, 4, "%s: unmapped addr %p for FD %d ID %x shmid %x", __PRETTY_FUNCTION__, shmaddr, shmem[idx].descriptor, idx, shmem[idx].id);
	if (shmem[idx].markedForDeletion) {
		VERBOSE(tracee, 4, "%s: deleting shmid %x", __PRETTY_FUNCTION__, shmem[idx].id);
		android_shmem_delete(idx);
	}
	return 0;

}

/* Shared memory control operation. */
int handle_shmctl_sysenter_end(Tracee *tracee, RegVersion stage)
{
	int shmid = (int)peek_reg(tracee, stage, SYSARG_1);
	int cmd = (int)peek_reg(tracee, stage, SYSARG_2);
	struct shmid_ds *buf = (struct shmid_ds *)peek_reg(tracee, stage, SYSARG_3);
	struct shmid_ds lcl_buf;

	if (cmd == IPC_RMID) {
		VERBOSE(tracee, 4, "%s: IPC_RMID for shmid=%x", __PRETTY_FUNCTION__, shmid);
		int idx = ashv_find_index(shmid);
		if (idx == -1) {
			VERBOSE(tracee, 4, "%s: shmid=%x does not exist locally", __PRETTY_FUNCTION__, shmid);
			/* Does not exist, but do not report an error for that. */
			poke_reg(tracee, SYSARG_RESULT, (word_t)0);
			return 0;
		}

		if (shmem[idx].addr) {
			// shmctl(2): The segment will actually be destroyed only
			// after the last process detaches it (i.e., when the shm_nattch
			// member of the associated structure shmid_ds is zero.
			shmem[idx].markedForDeletion = true;
		} else {
			android_shmem_delete(idx);
		}
		poke_reg(tracee, SYSARG_RESULT, (word_t)0);
		return 0;
	} else if (cmd == IPC_STAT) {
		if (!buf) {
			VERBOSE(tracee, 4, "%s: ERROR: buf == NULL for shmid %x", __PRETTY_FUNCTION__, shmid);
			return -EINVAL;
		}

		int idx = ashv_find_index(shmid);
		if (idx == -1) {
			VERBOSE(tracee, 4, "%s: ERROR: shmid %x does not exist", __PRETTY_FUNCTION__, shmid);
			return -EINVAL;
		}
		/* Report max permissive mode */
		memset(&lcl_buf, 0, sizeof(struct shmid_ds));
		lcl_buf.shm_segsz = shmem[idx].size;
		lcl_buf.shm_nattch = 1;
		lcl_buf.shm_perm.key = shmem[idx].key;
		//CCX need to get these from prooted process
		lcl_buf.shm_perm.uid = geteuid();
		lcl_buf.shm_perm.gid = getegid();
		lcl_buf.shm_perm.cuid = geteuid();
		lcl_buf.shm_perm.cgid = getegid();
		lcl_buf.shm_perm.mode = 0666;
		lcl_buf.shm_perm.seq = 1;
		write_data(tracee, peek_reg(tracee, stage, SYSARG_3), &lcl_buf, sizeof(struct shmid_ds));

		poke_reg(tracee, SYSARG_RESULT, (word_t)0);
		return 0;
	}

	VERBOSE(tracee, 4, "%s: cmd %d not implemented yet!", __PRETTY_FUNCTION__, cmd);
	return -EINVAL;
}

/* Just turn shared memory system calls into something harmless.
 * We will hande them on exit */
static int handle_sysenter_end(Tracee *tracee, RegVersion stage)
{
	word_t sysnum;

	sysnum = get_sysnum(tracee, ORIGINAL);
	switch (sysnum) {

	/* void *shmat(int shmid, const void *shmaddr, int shmflg); */
	case PR_shmat:
		return handle_shmat_sysenter_end(tracee, stage);
	/* int shmctl(int shmid, int cmd, struct shmid_ds *buf); */
	case PR_shmctl:
		return handle_shmctl_sysenter_end(tracee, stage);
	/* int shmdt(const void *shmaddr); */
	case PR_shmdt:
		return handle_shmdt_sysenter_end(tracee, stage);
	/* int shmget(key_t key, size_t size, int shmflg); */
	case PR_shmget:
		return handle_shmget_sysenter_end(tracee, stage);
	default:
		return 0;
	}

	return 0;
}

/* Just turn shared memory system calls into something harmless.
 * We will hande them on exit */
static int handle_sysexit_end(Tracee *tracee)
{
	word_t sysnum;

	sysnum = get_sysnum(tracee, ORIGINAL);
	switch (sysnum) {

	case PR_shmat: 
		return handle_shmat_sysexit_end(tracee);
	case PR_shmdt:
		return handle_shmdt_sysexit_end(tracee);
	case PR_shmctl:
	case PR_shmget:
		poke_reg(tracee, SYSARG_RESULT, (word_t)0);
		return 0;
	default:
		return 0;
	}

	return 0;
}

/**
 * Handler for this @extension.  It is triggered each time an @event
 * occured.  See ExtensionEvent for the meaning of @data1 and @data2.
 */
int shmem_callback(Extension *extension, ExtensionEvent event,
	intptr_t data1 UNUSED, intptr_t data2 UNUSED)
{
	switch (event) {
	case INITIALIZATION: {
	/* List of syscalls handled by this extension */
		static FilteredSysnum filtered_sysnums[] = {
			{ PR_shmat, FILTER_SYSEXIT },
			{ PR_shmctl, FILTER_SYSEXIT },
			{ PR_shmdt, FILTER_SYSEXIT },
			{ PR_shmget, FILTER_SYSEXIT },
			FILTERED_SYSNUM_END,
		};
		extension->filtered_sysnums = filtered_sysnums;
		return 0;
	}

	case SYSCALL_ENTER_END: {
		return handle_sysenter_end(TRACEE(extension), ORIGINAL);
	}

	case SYSCALL_EXIT_END: {
		return handle_sysexit_end(TRACEE(extension));
	}

	case SIGSYS_OCC: {
		int status;
		word_t sysnum;

		sysnum = get_sysnum(TRACEE(extension), CURRENT);
		switch (sysnum) {

		case PR_shmat:
		case PR_shmdt:
			status = handle_sysenter_end(TRACEE(extension), CURRENT);
			if (status < 0)
				return status;
			return 2;
		case PR_shmctl:
		case PR_shmget:
			status = handle_sysenter_end(TRACEE(extension), CURRENT);
			if (status < 0)
				return status;
			return 1;
		default:
			return 0;
		}

		return 0;
	}
	default:
		return 0;

	}
}
