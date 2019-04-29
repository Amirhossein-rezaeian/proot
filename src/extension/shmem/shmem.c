#include <android/log.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/un.h>
#include <unistd.h>
#include <paths.h>
#include <linux/limits.h>

#define __u32 uint32_t
#include <linux/ashmem.h>

#include "shm.h"

#include "extension/extension.h"
#include "tracee/mem.h"
#include "path/path.h"

#define DBG(...) __android_log_print(ANDROID_LOG_INFO, "shmem", __VA_ARGS__)
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

static void android_shmem_delete(int idx)
{
	if (shmem[idx].descriptor) close(shmem[idx].descriptor);
	shmem_amount--;
	memmove(&shmem[idx], &shmem[idx+1], (shmem_amount - idx) * sizeof(shmem_t));
}

/* Get shared memory area identifier. */
int shmget(key_t key, size_t size, int flags, Tracee *tracee)
{
	(void) flags;
	char path[PATH_MAX];

	static size_t shmem_counter = 0;

	int shmid = -1;

	if (key != IPC_PRIVATE) {
		int key_idx = ashv_find_key(key);
		if (key_idx != -1) {
			return shmem[key_idx].id;
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
		DBG("%s: ashmem_create_region() failed for size %zu: %s", __PRETTY_FUNCTION__, size, strerror(errno));
		shmem_amount --;
		shmem = realloc(shmem, shmem_amount * sizeof(shmem_t));
		return -1;
	}

	return shmid;
}

/* Attach shared memory segment. */
void* shmat(int shmid, void const* shmaddr, int shmflg)
{
	void *addr;

	int idx = ashv_find_index(shmid);
	if (idx == -1) {
		DBG ("%s: shmid %x does not exist", __PRETTY_FUNCTION__, shmid);
		errno = EINVAL;
		return (void*) -1;
	}

	if (shmem[idx].addr == NULL) {
		//CCX replace system call with this
		shmem[idx].addr = mmap((void*) shmaddr, shmem[idx].size, PROT_READ | (shmflg == 0 ? PROT_WRITE : 0), MAP_SHARED, shmem[idx].descriptor, 0);
		if (shmem[idx].addr == MAP_FAILED) {
			DBG ("%s: mmap() failed for ID %x FD %d: %s", __PRETTY_FUNCTION__, idx, shmem[idx].descriptor, strerror(errno));
			shmem[idx].addr = NULL;
		}
	}
	addr = shmem[idx].addr;
	DBG ("%s: mapped addr %p for FD %d ID %d", __PRETTY_FUNCTION__, addr, shmem[idx].descriptor, idx);

	return addr ? addr : (void *)-1;
}

/* Detach shared memory segment. */
int shmdt(void const* shmaddr)
{
	for (size_t i = 0; i < shmem_amount; i++) {
		if (shmem[i].addr == shmaddr) {
			//CCX replace with this system call
			if (munmap(shmem[i].addr, shmem[i].size) != 0) {
				DBG("%s: munmap %p failed", __PRETTY_FUNCTION__, shmaddr);
			}
			shmem[i].addr = NULL;
			DBG("%s: unmapped addr %p for FD %d ID %zu shmid %x", __PRETTY_FUNCTION__, shmaddr, shmem[i].descriptor, i, shmem[i].id);
			if (shmem[i].markedForDeletion) {
				DBG ("%s: deleting shmid %x", __PRETTY_FUNCTION__, shmem[i].id);
				android_shmem_delete(i);
			}
			return 0;
		}
	}

	DBG("%s: invalid address %p", __PRETTY_FUNCTION__, shmaddr);
	/* Could be a removed segment, do not report an error for that. */
	return 0;
}

/* Shared memory control operation. */
int shmctl(int shmid, int cmd, struct shmid_ds *buf)
{
	if (cmd == IPC_RMID) {
		DBG("%s: IPC_RMID for shmid=%x", __PRETTY_FUNCTION__, shmid);
		int idx = ashv_find_index(shmid);
		if (idx == -1) {
			DBG("%s: shmid=%x does not exist locally", __PRETTY_FUNCTION__, shmid);
			/* We do not rm non-local regions, but do not report an error for that. */
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
		return 0;
	} else if (cmd == IPC_STAT) {
		if (!buf) {
			DBG ("%s: ERROR: buf == NULL for shmid %x", __PRETTY_FUNCTION__, shmid);
			errno = EINVAL;
			return -1;
		}

		int idx = ashv_find_index(shmid);
		if (idx == -1) {
			DBG ("%s: ERROR: shmid %x does not exist", __PRETTY_FUNCTION__, shmid);
			errno = EINVAL;
			return -1;
		}
		/* Report max permissive mode */
		memset(buf, 0, sizeof(struct shmid_ds));
		buf->shm_segsz = shmem[idx].size;
		buf->shm_nattch = 1;
		buf->shm_perm.key = shmem[idx].key;
		//CCX need to get these from prooted process
		buf->shm_perm.uid = geteuid();
		buf->shm_perm.gid = getegid();
		buf->shm_perm.cuid = geteuid();
		buf->shm_perm.cgid = getegid();
		buf->shm_perm.mode = 0666;
		buf->shm_perm.seq = 1;

		return 0;
	}

	DBG("%s: cmd %d not implemented yet!", __PRETTY_FUNCTION__, cmd);
	errno = EINVAL;
	return -1;
}

/* Just turn shared memory system calls into something harmless.
 * We will hande them on exit */
static int handle_sysenter_end(Tracee *tracee)
{
	word_t sysnum;

	sysnum = get_sysnum(tracee, ORIGINAL);
	switch (sysnum) {

	case PR_shmat:
	case PR_shmctl:
	case PR_shmdt:
	case PR_shmget:
		set_sysnum(tracee, PR_getuid);
		return 0;
	default:
		return 0;
	}

	return 0;
}

/* Just turn shared memory system calls into something harmless.
 * We will hande them on exit */
static int handle_sysexit_end(Tracee *tracee, RegVersion stage)
{
	word_t sysnum;

	sysnum = get_sysnum(tracee, stage);
	switch (sysnum) {

	/* void *shmat(int shmid, const void *shmaddr, int shmflg); */
	case PR_shmat: {
		int shmid = (int)peek_reg(tracee, stage, SYSARG_1);
		void *shmaddr = (void *)peek_reg(tracee, stage, SYSARG_2);
		int shmflg = (int)peek_reg(tracee, stage, SYSARG_3);
		int result = (word_t)shmat(shmid, shmaddr, shmflg);
		poke_reg(tracee, SYSARG_RESULT, (word_t)result);
		if (result < 0)
			return result;
	}
	/* int shmctl(int shmid, int cmd, struct shmid_ds *buf); */
	case PR_shmctl: {
		int shmid = (int)peek_reg(tracee, stage, SYSARG_1);
		int cmd = (int)peek_reg(tracee, stage, SYSARG_2);
		struct shmid_ds buf;
		read_data(tracee, &buf, peek_reg(tracee, stage, SYSARG_3), sizeof(struct shmid_ds));
		int result = (word_t)shmctl(shmid, cmd, &buf);
		poke_reg(tracee, SYSARG_RESULT, (word_t)result);
		if (result < 0)
			return result;
	}
	/* int shmdt(const void *shmaddr); */
	case PR_shmdt: {
		void *shmaddr = (void *)peek_reg(tracee, stage, SYSARG_1);
		int result = (word_t)shmdt(shmaddr);
		poke_reg(tracee, SYSARG_RESULT, (word_t)result);
		if (result < 0)
			return result;
	}
	/* int shmget(key_t key, size_t size, int shmflg); */
	case PR_shmget: {
		key_t key = (key_t)peek_reg(tracee, stage, SYSARG_1);
		size_t size = (size_t)peek_reg(tracee, stage, SYSARG_2);
		int flags = (int)peek_reg(tracee, stage, SYSARG_3);
		int result = (word_t)shmget(key, size, flags, tracee);
		poke_reg(tracee, SYSARG_RESULT, (word_t)result);
		if (result < 0)
			return result;
	}
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
		return handle_sysenter_end(TRACEE(extension));
	}

	case SYSCALL_EXIT_END: {
		return handle_sysexit_end(TRACEE(extension), ORIGINAL);
	}

	case SIGSYS_OCC: {
		int status;
		word_t sysnum;

		sysnum = get_sysnum(TRACEE(extension), CURRENT);
		switch (sysnum) {

		case PR_shmat:
		case PR_shmctl:
		case PR_shmdt:
		case PR_shmget:
			status = handle_sysexit_end(TRACEE(extension), CURRENT);
			if (status < 0)
				return status;
			break;
		default:
			return 0;
		}

		return 1;
	}
	default:
		return 0;

	}
}
