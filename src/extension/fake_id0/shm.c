#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <paths.h>
#include <linux/limits.h>

#define __u32 uint32_t
#include <linux/ashmem.h>

#include "extension/extension.h"
#include "cli/note.h"
#include "tracee/mem.h"
#include "path/path.h"
#include "syscall/chain.h"

#include "extension/fake_id0/shm.h"

#define ANDROID_SHMEM_SOCKNAME "/dev/shm/%08x"
#define ROUND_UP(N, S) ((((N) + (S) - 1) / (S)) * (S))

typedef struct {
	int id;
	void **addr;
	int descriptor;
	size_t size;
	int nattach;
	bool markedForDeletion;
	key_t key;
} shmem_t;

static shmem_t* shmem = NULL;
static size_t shmem_amount = 0;

// The lower 16 bits of (getpid() + i), where i is a sequence number.
// It is unique among processes as it's only set when bound.
static int ashv_local_socket_id = 0;

static pthread_t ashv_listening_thread_id = 0;

static int ancil_send_fd(int sock, int fd)
{
	char nothing = '!';
	struct iovec nothing_ptr = { .iov_base = &nothing, .iov_len = 1 };

	struct {
		struct cmsghdr align;
		int fd[1];
	} ancillary_data_buffer;

	struct msghdr message_header = {
		.msg_name = NULL,
		.msg_namelen = 0,
		.msg_iov = &nothing_ptr,
		.msg_iovlen = 1,
		.msg_flags = 0,
		.msg_control = &ancillary_data_buffer,
		.msg_controllen = sizeof(struct cmsghdr) + sizeof(int)
	};

	struct cmsghdr* cmsg = CMSG_FIRSTHDR(&message_header);
	cmsg->cmsg_len = message_header.msg_controllen; // sizeof(int);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	((int*) CMSG_DATA(cmsg))[0] = fd;

	return sendmsg(sock, &message_header, 0) >= 0 ? 0 : -1;
}

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

static int ashv_find_addr(void *addr)
{
	for (size_t i = 0; i < shmem_amount; i++)
		for (int j = 0; j < shmem[i].nattach; j++)
			if (shmem[i].addr[j] == addr)
				return i;
	return -1;
}

static void android_shmem_addr_attach(int idx, void *addr)
{
	shmem[idx].nattach++;
	shmem[idx].addr = realloc(shmem[idx].addr, shmem[idx].nattach * sizeof(void *));
	shmem[idx].addr[shmem[idx].nattach-1] = addr;
}

static void android_shmem_addr_detach(int idx, void *addr)
{
	for (int i = 0; i < shmem[idx].nattach; i++)
		if (shmem[idx].addr[i] == addr) {
			shmem[idx].nattach--;
			memmove(&(shmem[idx].addr[i]), &(shmem[idx].addr[i+1]), (shmem[idx].nattach - i) * sizeof(void *));
			return;
		}
}

static void* ashv_thread_function(void* arg)
{
	int sock = *(int*)arg;
	free(arg);
	struct sockaddr_un addr;
	socklen_t len = sizeof(addr);
	int sendsock;
	Tracee *tracee = NULL;
	while ((sendsock = accept(sock, (struct sockaddr *)&addr, &len)) != -1) {
		int shmid;
		if (recv(sendsock, &shmid, sizeof(shmid), 0) != sizeof(shmid)) {
			VERBOSE(tracee, 4, "%s: ERROR: recv() returned not %zu bytes", __PRETTY_FUNCTION__, sizeof(shmid));
			close(sendsock);
			continue;
		}
		int idx = ashv_find_index(shmid);
		if (idx != -1) {
			if (write(sendsock, &shmem[idx].key, sizeof(key_t)) != sizeof(key_t)) {
				VERBOSE(tracee, 4, "%s: ERROR: write failed: %s", __PRETTY_FUNCTION__, strerror(errno));
			}
			if (ancil_send_fd(sendsock, shmem[idx].descriptor) != 0) {
				VERBOSE(tracee, 4, "%s: ERROR: ancil_send_fd() failed: %s", __PRETTY_FUNCTION__, strerror(errno));
			}
		} else {
			VERBOSE(tracee, 4, "%s: ERROR: cannot find shmid 0x%x", __PRETTY_FUNCTION__, shmid);
		}
		close(sendsock);
		len = sizeof(addr);
	}
	VERBOSE(tracee, 4, "%s: ERROR: listen() failed, thread stopped", __PRETTY_FUNCTION__);
	return NULL;
}

/* Get shared memory area identifier. */
int handle_shmget_sysexit_end(Tracee *tracee, RegVersion stage)
{
	static size_t shmem_counter = 0;
	int shmid = -1;
	key_t key = (key_t)peek_reg(tracee, stage, SYSARG_1);
	size_t size = (size_t)peek_reg(tracee, stage, SYSARG_2);

	VERBOSE(tracee, 4, "%s: Emulating shmget", __PRETTY_FUNCTION__);

	if (!ashv_listening_thread_id) {
		int sock = socket(AF_UNIX, SOCK_STREAM, 0);
		if (!sock) {
			VERBOSE(tracee, 4, "%s: cannot create UNIX socket: %s", __PRETTY_FUNCTION__, strerror(errno));
			errno = EINVAL;
			return -1;
		}
		int i;
		for (i = 0; i < 4096; i++) {
			struct sockaddr_un addr;
			int len;
			memset (&addr, 0, sizeof(addr));
			addr.sun_family = AF_UNIX;
			ashv_local_socket_id = (getpid() + i) & 0xffff;
			sprintf(&addr.sun_path[1], ANDROID_SHMEM_SOCKNAME, ashv_local_socket_id);
			len = sizeof(addr.sun_family) + strlen(&addr.sun_path[1]) + 1;
			if (bind(sock, (struct sockaddr *)&addr, len) != 0) continue;
			VERBOSE(tracee, 4, "%s: bound UNIX socket %s in pid=%d", __PRETTY_FUNCTION__, addr.sun_path + 1, getpid());
			break;
		}
		if (i == 4096) {
			VERBOSE(tracee, 4, "%s: cannot bind UNIX socket, bailing out", __PRETTY_FUNCTION__);
			ashv_local_socket_id = 0;
			errno = ENOMEM;
			return -1;
		}
		if (listen(sock, 4) != 0) {
			VERBOSE(tracee, 4, "%s: listen failed", __PRETTY_FUNCTION__);
			errno = ENOMEM;
			return -1;
		}
		int* socket_arg = malloc(sizeof(int));
		*socket_arg = sock;
		pthread_create(&ashv_listening_thread_id, NULL, &ashv_thread_function, socket_arg);
	}

	if (key != IPC_PRIVATE) {
		int key_idx = ashv_find_key(key);
		if (key_idx != -1) {
			poke_reg(tracee, SYSARG_RESULT, (word_t)shmem[key_idx].id);
			return 0;
		}
	}

	int idx = shmem_amount;
	char buf[256];
	sprintf(buf, ANDROID_SHMEM_SOCKNAME "-%d", ashv_local_socket_id, idx);

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
	shmem[idx].nattach = 0;
	shmem[idx].markedForDeletion = false;
	shmem[idx].key = key;

	if (shmem[idx].descriptor < 0) {
		VERBOSE(tracee, 4, "%s: ashmem_create_region() failed for size %zu: %s", __PRETTY_FUNCTION__, size, strerror(errno));
		shmem_amount --;
		shmem = realloc(shmem, shmem_amount * sizeof(shmem_t));
		poke_reg(tracee, SYSARG_RESULT, (word_t)-1);
		return 0;
	} else {
		VERBOSE(tracee, 4, "%s: ashmem_create_region() worked. shmem[%d].descriptor = %d", __PRETTY_FUNCTION__, idx, shmem[idx].descriptor);
	}

	poke_reg(tracee, SYSARG_RESULT, (word_t)shmid);
	return 0;
}

/* Attach shared memory segment. */
int handle_shmat_sysenter_end(Tracee *tracee, RegVersion stage)
{
	int shmid = (int)peek_reg(tracee, stage, SYSARG_1);
	int idx = ashv_find_index(shmid);
	if (idx == -1) {
		VERBOSE(tracee, 4, "%s: shmid %x does not exist", __PRETTY_FUNCTION__, shmid);
		return -EINVAL;
	}

	set_sysnum(tracee, PR_socket);
	poke_reg(tracee, SYSARG_1, AF_UNIX);
	poke_reg(tracee, SYSARG_2, SOCK_STREAM);
	poke_reg(tracee, SYSARG_3, 0);

	//Allocate memory we are going to need later
	tracee->word_store[0] = alloc_mem(tracee, sizeof(struct sockaddr_un));
	tracee->word_store[1] = alloc_mem(tracee, sizeof(int));
	tracee->word_store[2] = alloc_mem(tracee, sizeof(key_t));
	tracee->word_store[3] = alloc_mem(tracee, 1);
	tracee->word_store[4] = alloc_mem(tracee, sizeof(struct iovec));
	struct {
		struct cmsghdr align;
		int fd[1];
	} ancillary_data_buffer;
	tracee->word_store[5] = alloc_mem(tracee, sizeof(ancillary_data_buffer));
	tracee->word_store[6] = alloc_mem(tracee, sizeof(struct msghdr));

	return 0;
}

/* Attach shared memory segment. */
int handle_shmat_sysexit_end(Tracee *tracee, RegVersion stage)
{
	word_t sysnum;
	word_t result;
	int shmid;

	sysnum = get_sysnum(tracee, CURRENT);
	switch (sysnum) {
	case PR_socket:
		result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
		if ((int)result < 0) {
			VERBOSE(tracee, 4, "%s: cannot create UNIX socket", __PRETTY_FUNCTION__);
			return -EINVAL;
		}
		struct sockaddr_un sockaddr;
		memset(&sockaddr, 0, sizeof(sockaddr));
		sockaddr.sun_family = AF_UNIX;
		sprintf(&sockaddr.sun_path[1], ANDROID_SHMEM_SOCKNAME, ashv_local_socket_id);
		int addrlen = sizeof(sockaddr.sun_family) + strlen(&sockaddr.sun_path[1]) + 1;
		write_data(tracee, tracee->word_store[0], &sockaddr, sizeof(struct sockaddr_un));
		tracee->word_store[8] = result;
		tracee->word_store[9] = (word_t)-1;
		register_chained_syscall(tracee, PR_connect, result, tracee->word_store[0], addrlen, 0, 0, 0);
		return 0;
	case PR_connect:
		result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
		if ((int)result != 0) {
			VERBOSE(tracee, 4, "%s: Cannot connect to UNIX socket", __PRETTY_FUNCTION__);
			return -EINVAL;
		}
		shmid = (int)peek_reg(tracee, stage, SYSARG_1);
		write_data(tracee, tracee->word_store[1], &shmid, sizeof(int));
		register_chained_syscall(tracee, PR_sendto, tracee->word_store[8], tracee->word_store[1], sizeof(int), 0, 0, 0);
		return 0;
	case PR_sendto:
		result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
		if ((int)result != sizeof(shmid)) {
			VERBOSE(tracee, 4, "%s: send() failed on socket", __PRETTY_FUNCTION__);
			register_chained_syscall(tracee, PR_close, tracee->word_store[8], 0, 0, 0, 0, 0);
			return 0;
		}
		register_chained_syscall(tracee, PR_read, tracee->word_store[8], tracee->word_store[2], sizeof(key_t), 0, 0, 0);
		return 0;
	case PR_read:
		result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
		if ((int)result != sizeof(key_t)) {
			VERBOSE(tracee, 4, "%s: read() failed on socket", __PRETTY_FUNCTION__);
			register_chained_syscall(tracee, PR_close, tracee->word_store[8], 0, 0, 0, 0, 0);
			return 0;
		}

		char nothing = '!';
		write_data(tracee, tracee->word_store[3], &nothing, 1);
		struct iovec nothing_ptr = { .iov_base = (void *)tracee->word_store[3], .iov_len = 1 };
		write_data(tracee, tracee->word_store[4], &nothing_ptr, sizeof(nothing_ptr));

		struct {
			struct cmsghdr align;
			int fd[1];
		} ancillary_data_buffer;
		ancillary_data_buffer.fd[0] = -1;
		write_data(tracee, tracee->word_store[5], &ancillary_data_buffer, sizeof(ancillary_data_buffer));

		struct msghdr message_header = {
			.msg_name = NULL,
			.msg_namelen = 0,
			.msg_iov = (struct iovec *)tracee->word_store[4],
			.msg_iovlen = 1,
			.msg_flags = 0,
			.msg_control = (void *)tracee->word_store[5],
			.msg_controllen = sizeof(struct cmsghdr) + sizeof(int)
		};
		write_data(tracee, tracee->word_store[6], &message_header, sizeof(struct msghdr));

		register_chained_syscall(tracee, PR_recvmsg, tracee->word_store[8], tracee->word_store[6], 0, 0, 0, 0);
		return 0;
	case PR_recvmsg:
		result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
		if ((int)result < 0) {
			VERBOSE(tracee, 4, "%s: recvmesg() failed on socket", __PRETTY_FUNCTION__);
			register_chained_syscall(tracee, PR_close, tracee->word_store[8], 0, 0, 0, 0, 0);
			return 0;
		}

		struct msghdr message_header_2;
		read_data(tracee, &message_header_2, tracee->word_store[6], sizeof(struct msghdr));

		struct {
			struct cmsghdr align;
			int fd[1];
		} ancillary_data_buffer_2;
		read_data(tracee, &ancillary_data_buffer_2, (word_t)message_header_2.msg_control, sizeof(ancillary_data_buffer_2));

		tracee->word_store[9] = ancillary_data_buffer_2.fd[0];
		register_chained_syscall(tracee, PR_close, tracee->word_store[8], 0, 0, 0, 0, 0);
		return 0;
	case PR_close: {
		if ((int)tracee->word_store[9] == -1)
			return -EINVAL;

		int shmid = (int)peek_reg(tracee, stage, SYSARG_1);
		void *shmaddr = (void *)peek_reg(tracee, stage, SYSARG_2);
		int shmflg = (int)peek_reg(tracee, stage, SYSARG_3);
		int idx = ashv_find_index(shmid);
		if (idx == -1) {
			VERBOSE(tracee, 4, "%s: shmid %x does not exist", __PRETTY_FUNCTION__, shmid);
			return -EINVAL;
		}

		word_t mmap_sysnum = detranslate_sysnum(get_abi(tracee), PR_mmap2) != SYSCALL_AVOIDER
                        ? PR_mmap2
                        : PR_mmap;
		register_chained_syscall(tracee, mmap_sysnum, (word_t)shmaddr, (word_t)shmem[idx].size, (word_t)(PROT_READ | (shmflg == 0 ? PROT_WRITE : 0)), (word_t)MAP_SHARED, tracee->word_store[9], 0);
		return 0;
	}
	case PR_mmap:
	case PR_mmap2: {
		result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
		if ((void *)result == MAP_FAILED) {
			VERBOSE(tracee, 4, "%s: mmap() failed", __PRETTY_FUNCTION__);
			return -EINVAL;
		}

		int shmid = (int)peek_reg(tracee, stage, SYSARG_1);
		int idx = ashv_find_index(shmid);
		if (idx == -1) {
			VERBOSE(tracee, 4, "%s: shmid %x does not exist", __PRETTY_FUNCTION__, shmid);
			return -EINVAL;
		}
		android_shmem_addr_attach(idx, (void *)result);
		VERBOSE(tracee, 4, "%s: shmid %x, nattach %d", __PRETTY_FUNCTION__, shmid, shmem[idx].nattach);
		return 0;
	}
	default:
		return 0;
	}

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
	android_shmem_addr_detach(idx, shmaddr);
	VERBOSE(tracee, 4, "%s: unmapped addr %p for FD %d ID %x shmid %x", __PRETTY_FUNCTION__, shmaddr, shmem[idx].descriptor, idx, shmem[idx].id);
	VERBOSE(tracee, 4, "%s: shmid %x, nattach %d", __PRETTY_FUNCTION__, shmem[idx].id, shmem[idx].nattach);
	if (shmem[idx].markedForDeletion && (shmem[idx].nattach == 0)) {
		VERBOSE(tracee, 4, "%s: deleting shmid %x", __PRETTY_FUNCTION__, shmem[idx].id);
		android_shmem_delete(idx);
	}
	return 0;

}

/* Shared memory control operation. */
int handle_shmctl_sysexit_end(Tracee *tracee, Config *config, RegVersion stage)
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

		if (shmem[idx].nattach != 0) {
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
		lcl_buf.shm_nattch = shmem[idx].nattach;
		lcl_buf.shm_perm.key = shmem[idx].key;
		lcl_buf.shm_perm.uid = config->euid;
		lcl_buf.shm_perm.gid = config->egid;
		lcl_buf.shm_perm.cuid = config->euid;
		lcl_buf.shm_perm.cgid = config->egid;
		lcl_buf.shm_perm.mode = 0666;
		lcl_buf.shm_perm.seq = 1;
		write_data(tracee, peek_reg(tracee, stage, SYSARG_3), &lcl_buf, sizeof(struct shmid_ds));

		poke_reg(tracee, SYSARG_RESULT, (word_t)0);
		return 0;
	}

	VERBOSE(tracee, 4, "%s: cmd %d not implemented yet!", __PRETTY_FUNCTION__, cmd);
	return -EINVAL;
}
