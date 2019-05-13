#include <sys/ipc.h>

#include "extension/extension.h"
#include "cli/note.h"
#include "tracee/mem.h"
#include "path/path.h"

#include "extension/fake_id0/sem.h"

#define SEM_UNDO 0x1000

#define GETPID 11  
#define GETVAL 12  
#define GETALL 13  
#define GETNCNT 14  
#define GETZCNT 15  
#define SETVAL 16  
#define SETALL 17  
#define SEM_STAT 18
#define SEM_INFO 19

struct  seminfo {
	int semmap;  /* Number of entries in semaphore
	                map; unused within kernel */
	int semmni;  /* Maximum number of semaphore sets */
	int semmns;  /* Maximum number of semaphores in all
	                semaphore sets */
	int semmnu;  /* System-wide maximum number of undo
	                structures; unused within kernel */
	int semmsl;  /* Maximum number of semaphores in a
	                set */
	int semopm;  /* Maximum number of operations for
	                semop(2) */
	int semume;  /* Maximum number of undo entries per
	                process; unused within kernel */
	int semusz;  /* Size of struct sem_undo */
	int semvmx;  /* Maximum semaphore value */
	int semaem;  /* Max. value that can be recorded for
	                semaphore adjustment (SEM_UNDO) */
};

struct semid_ds {
	struct ipc_perm sem_perm;  /* Ownership and permissions */
	time_t          sem_otime; /* Last semop time */
	time_t          sem_ctime; /* Last change time */
	int             sem_nsems; /* No. of semaphores in set */
};

union semun {
	int              val;    /* Value for SETVAL */
	struct semid_ds *buf;    /* Buffer for IPC_STAT, IPC_SET */
	unsigned short  *array;  /* Array for GETALL, SETALL */
	struct seminfo  *__buf;  /* Buffer for IPC_INFO
	                            (Linux-specific) */
};

struct sembuf {
	unsigned short sem_num;
	short sem_op;
	short sem_flg;
};

typedef struct {
        int id;
	struct semid_ds semds;
	int *semvals;
} sem_t;

static sem_t *sems = NULL;
static size_t sem_cnt = 0;

static int sem_find_index(int semid)
{
	for (size_t i = 0; i < sem_cnt; i++)
		if (sems[i].id == semid)
			return i;
	return -1;
}

static int sem_find_key(key_t key)
{
	for (size_t i = 0; i < sem_cnt; i++)
		if (sems[i].semds.sem_perm.key == key)
			return i;
	return -1;
}

int handle_semget_sysexit_end(Tracee *tracee, RegVersion stage)
{
	static size_t sem_counter = 0;
	int semid = -1;

	key_t key = (key_t)peek_reg(tracee, stage, SYSARG_1);
	int nsems = (int)peek_reg(tracee, stage, SYSARG_2);
	int flags = (int)peek_reg(tracee, stage, SYSARG_3);

	VERBOSE(tracee, 4, "%s: Emulating semget", __PRETTY_FUNCTION__);

	int key_idx = -1;
		
	if (key != IPC_PRIVATE) 
		key_idx = sem_find_key(key);

	//Return an error if IPC_CREAT and IPC_EXCL are specified and the key already exists
	if (((flags & (IPC_CREAT | IPC_EXCL)) == (IPC_CREAT | IPC_EXCL)) && (key_idx != -1))
		return -EEXIST;

	//nsems must be >= 0
	if (nsems < 0)
		return -EINVAL;

	//If we are not asked to create a new one, one better exist
	if ((key != IPC_PRIVATE) && ((flags & IPC_CREAT) == 0) && (key_idx == -1)) 
		return -ENOENT;

	//If we are not forced to create one and one already exists, check nsems and then return 
	if ((key != IPC_PRIVATE) && (key_idx != -1)) { 
		if (nsems > sems[key_idx].semds.sem_nsems)
			return -EINVAL;

		poke_reg(tracee, SYSARG_RESULT, (word_t)sems[key_idx].id);
		return 0;
	}

	//Create a new semaphore
	
	//nsems must be > 0 when creating
	if (nsems <= 0)
		return -EINVAL;

	int idx = sem_cnt;
	sem_cnt++;
	sem_counter = sem_counter + 1;
	semid = sem_counter;
	sems = realloc(sems, sem_cnt * sizeof(sem_t));

	sems[idx].id = semid;
	sems[idx].semds.sem_nsems = nsems;
	sems[idx].semds.sem_perm.key = key;
	sems[idx].semvals = calloc(nsems, sizeof(int));

	poke_reg(tracee, SYSARG_RESULT, (word_t)semid);
	return 0;
}

int handle_semctl_sysexit_end(Tracee *tracee, RegVersion stage)
{
	int semid = (int)peek_reg(tracee, stage, SYSARG_1);
	int semnum = (int)peek_reg(tracee, stage, SYSARG_2);
	int cmd = (int)peek_reg(tracee, stage, SYSARG_3);
	int idx = sem_find_index(semid);

	VERBOSE(tracee, 4, "%s: Emulating semctl", __PRETTY_FUNCTION__);

	if (idx < 0)
		return -EINVAL;

	switch (cmd) {
	case SETVAL:
		if (semnum >= sems[idx].semds.sem_nsems)
			return -EINVAL;
		sems[idx].semvals[semnum] = (int)peek_reg(tracee, stage, SYSARG_4);
		poke_reg(tracee, SYSARG_RESULT, 0);
		return 0;
	case GETVAL:
		if (semnum >= sems[idx].semds.sem_nsems)
			return -EINVAL;
		poke_reg(tracee, SYSARG_RESULT, (word_t)sems[idx].semvals[semnum]);
		return 0;
	}

	return 0;
}

int handle_semop_sysexit_end(Tracee *tracee, RegVersion stage)
{
	struct sembuf *my_sembuf = NULL;
	int semid = (int)peek_reg(tracee, stage, SYSARG_1);
	size_t nsops = (size_t)peek_reg(tracee, stage, SYSARG_3);
	int idx = sem_find_index(semid);

	VERBOSE(tracee, 4, "%s: Emulating semop", __PRETTY_FUNCTION__);

	if ((idx < 0) || (nsops < 1))
		return -EINVAL;

	my_sembuf = realloc(my_sembuf, nsops * sizeof(struct sembuf));
	read_data(tracee, my_sembuf, peek_reg(tracee, stage, SYSARG_2), nsops * sizeof(struct sembuf));
	//CCX need to be atomic - so need to check if everything can be done before modifying 
	for (size_t i = 0; i < nsops; i++) {
		VERBOSE(tracee, 4, "%s: my_sembuf[%zu].sem_num = %d", __PRETTY_FUNCTION__, i, my_sembuf[i].sem_num);
		VERBOSE(tracee, 4, "%s: my_sembuf[%zu].sem_op = %d", __PRETTY_FUNCTION__, i, my_sembuf[i].sem_op);
		VERBOSE(tracee, 4, "%s: my_sembuf[%zu].sem_flg = %d", __PRETTY_FUNCTION__, i, my_sembuf[i].sem_flg);
		if (my_sembuf[i].sem_op > 0) {
			sems[idx].semvals[my_sembuf[i].sem_num] += my_sembuf[i].sem_op; 
			poke_reg(tracee, SYSARG_RESULT, 0);
			return 0;
		} else if (my_sembuf[i].sem_op < 0) {
			if (sems[idx].semvals[my_sembuf[i].sem_num] < (-1*my_sembuf[i].sem_op))
				return -EAGAIN;
			sems[idx].semvals[my_sembuf[i].sem_num] += my_sembuf[i].sem_op;
			poke_reg(tracee, SYSARG_RESULT, 0);
			return 0;
		} else {
			if (sems[idx].semvals[my_sembuf[i].sem_num] != 0)
				return -EAGAIN;
			poke_reg(tracee, SYSARG_RESULT, 0);
			return 0;
		}
	}

	return 0;
}
