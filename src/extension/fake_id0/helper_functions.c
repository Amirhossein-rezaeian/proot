#include <linux/limits.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <leveldb/c.h>

#include "cli/note.h"
#include "syscall/syscall.h"
#include "syscall/sysnum.h"
#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "tracee/mem.h"
#include "path/path.h"
#include "extension/fake_id0/config.h"
#include "extension/fake_id0/helper_functions.h"

#define META_TAG ".proot-meta-file."

#define OWNER_PERMS	 0
#define GROUP_PERMS	 1
#define OTHER_PERMS	 2

#ifndef DB_PATH
#define DB_PATH "/support/meta_db"
#endif

leveldb_t *db;
leveldb_options_t *options;
leveldb_readoptions_t *roptions;
leveldb_writeoptions_t *woptions;

/** Converts a decimal number to its octal representation. Used to convert
 *  system returned modes to a more common form for humans.
 */
int dtoo(int n) 
{
	int rem, i=1, octal=0;
	while (n!=0)
	{
		rem=n%8;
		n/=8;
		octal+=rem*i;
		i*=10;
	}
	return octal;
}

/** Converts an octal number to its decimal representation. Used to return to a
 *  more machine-usable form of mode from human-readable.
 */
int otod(int n)
{
	int decimal=0, i=0, rem;
	while (n!=0)
	{
		int j;
		int pow = 1;
		for(j = 0; j < i; j++)
			pow = pow * 8;
		rem = n%10;
		n/=10;
		decimal += rem*pow;
		++i;
	}
	return decimal;
}

/** Determines whether the file specified by path exists.
 */
int path_exists(char path[PATH_MAX])
{
	return access(path, F_OK);  
}

/** Gets a path from file descriptor system argument. If that sysarg is
 *  IGNORE_FLAGS, it returns the root of the guestfs, and if the file
 *  descriptor refers to the cwd, it returns that. Returning the root
 *  is used in cases where the function is used to find relative paths
 *  for __at calls.
 */

int get_fd_path(Tracee *tracee, char path[PATH_MAX], Reg fd_sysarg, RegVersion version)
{
	int status;

	if(fd_sysarg != IGNORE_SYSARG) {
		// AT_CWD translates to -100, so replace it with a canonicalized version
		if((signed int) peek_reg(tracee, version, fd_sysarg) == -100) 
			status = getcwd2(tracee, path);

		else {
			// See read_sysarg_path for an explanation of the use of modified.
			status = readlink_proc_pid_fd(tracee->pid, peek_reg(tracee, version, fd_sysarg), path);
		}
		if(status < 0) 
			return status;
	}

	else 
		translate_path(tracee, path, AT_FDCWD, "/", true);
	
	/** If a path does not belong to the guestfs, a handler either exits with 0
	 *  or sets the syscall to void (in the case of chmod and chown.
	 */
	if(!belongs_to_guestfs(tracee, path))
		return 1;

	return 0;
}

/** Reads a path from path_sysarg into path.
 */

int read_sysarg_path(Tracee *tracee, char path[PATH_MAX], Reg path_sysarg, RegVersion version)
{
	int size;
	char original[PATH_MAX];
	/** Current is already canonicalized. . Modified is used here
	 *  for exit calls because on ARM architectures, the result to a system
	 *  call is placed in SYSARG_1. Using MODIFIED allows the original path to
	 *  be read. ORIGINAL is necessary in the case of execve(2) because of the
	 *  modifications that PRoot makes to the path of the executable.
	 */
	switch(version) {
		case MODIFIED:
			size = read_string(tracee, path, peek_reg(tracee, MODIFIED, path_sysarg), PATH_MAX);
			break;
		case CURRENT:
			size = read_string(tracee, path, peek_reg(tracee, CURRENT, path_sysarg), PATH_MAX);
			break;
		case ORIGINAL:
			size = read_string(tracee, original, peek_reg(tracee, ORIGINAL, path_sysarg), PATH_MAX);
			translate_path(tracee, path, AT_FDCWD, original, true);
			break;
		/* Never hit */
		default:
			size = 0;   //Shut the compiler up
			break;
	}

	if(size < 0)
		return size;
	if(size >= PATH_MAX)
		return -ENAMETOOLONG;

	/** If a path does not belong to the guestfs, a handler either exits with 0
	 *  or sets the syscall to void (in the case of chmod and chown). Checking
	 *  whether or not a path belongs to the guestfs only needs to happen if
	 *  that path actually exists. Removing this check will cause some package
	 *  installations to fail because they try to create symlinks with null
	 *  targets.
	 */
	if(strlen(path) > 0)
		if(!belongs_to_guestfs(tracee, path))
			return 1;

	return 0;
}

/** Gets the final component of a path.
 */
char * get_name(char path[PATH_MAX])
{
	char *name;
	int offset;

	offset = strlen(path) - 1;
	if ((path[offset] == '/') && (offset > 0)) 
		path[offset] = '\0';

	name = strrchr(path,'/');
	if (name == NULL)
		name = path;
	else
		name++;

	return name;
}

/** Returns the mode pertinent to the level of permissions the user has. Eg if
 *  uid 1000 tries to access a file it owns with mode 751, this returns 7.
 */
int get_permissions(char path[PATH_MAX], Config *config, bool uses_real)
{
	int perms;
	int omode;
	mode_t mode;
	uid_t owner, emulated_uid;
	gid_t group, emulated_gid;

	read_meta_info(path, &mode, &owner, &group, config);

	if (uses_real) {
		emulated_uid = config->ruid;
		emulated_gid = config->rgid;
	} else {
		emulated_uid = config->euid;
		emulated_gid = config->egid;
	}

	if (emulated_uid == owner || emulated_uid == 0)
		perms = OWNER_PERMS;
	else if(emulated_gid == group)
		perms = GROUP_PERMS;
	else
		perms = OTHER_PERMS;

	omode = dtoo(mode);
	switch(perms) {
	case OWNER_PERMS:
		omode /= 10;
	case GROUP_PERMS:
		omode /= 10;
	case OTHER_PERMS:
		omode = omode % 10;
	}

	/** Root always has RW permissions for every file. Has weird interactions
	 *  with sudo v su, EG su can echo into a file with perms of 400 but sudo cannot.
	 */
	if(emulated_uid == 0)
		omode |= 6;
	return omode;
}

/** Checks permissions on every component of path. Up to the location specifed
 *  by rel_path. If type is specified to be "read", it checks only execute 
 *  permissions. If type is specified to be "write", it makes sure that the 
 *  parent directory of the file specified by path also has write permissions.
 *  The permission check uses guest paths only.
 */
int check_dir_perms(Tracee *tracee, char type, char path[PATH_MAX], char rel_path[PATH_MAX], Config *config)
{
	int perms;
	char shorten_path[PATH_MAX];
	int x = 1; 
	int w = 2;

	get_dir_path(path, shorten_path);

	perms = get_permissions(shorten_path, config, 0);

	if(type == 'w' && (perms & w) != w) 
		return -EACCES;
	
	if(type == 'r' && (perms & x) != x) 
		return -EACCES;

	while(strcmp(shorten_path, rel_path) != 0 && strlen(rel_path) < strlen(shorten_path)) {
		get_dir_path(shorten_path, shorten_path);
		if(!belongs_to_guestfs(tracee, shorten_path))
			break;

		perms = get_permissions(shorten_path, config, 0);
		if((perms & x) != x) 
			return -EACCES;
	}

	return 0;
}

/** Gets a path without its final component.
 */
int get_dir_path(char path[PATH_MAX], char dir_path[PATH_MAX])
{
	int offset;

	strcpy(dir_path, path);
	offset = strlen(dir_path) - 1;
	if (offset > 0) {
		/* Skip trailing path separators. */
		while (offset > 1 && dir_path[offset] == '/')
			offset--;

		/* Search for the previous path separator. */
		while (offset > 1 && dir_path[offset] != '/')
			offset--;

		/* Cut the end of the string before the last component. */
		dir_path[offset] = '\0';
	}
	return 0;
}

/** Stores in meta_path the contents of orig_path with the addition of META_TAG
 *  to the final component.
 */
int get_meta_path(char orig_path[PATH_MAX], char meta_path[PATH_MAX]) 
{
	char *filename;

	/*Separate the final component from the path. */
	get_dir_path(orig_path, meta_path);
	filename = get_name(orig_path);

	/* Add a / between the final component and the rest of the path. */
	if(strcmp(meta_path, "/") != 0)
		strcat(meta_path, "/");

	if(strlen(meta_path) + strlen(filename) + strlen(META_TAG) >= PATH_MAX)
		return -ENAMETOOLONG;

	/* Insert the meta_tag between the path and its final component. */
	strcat(meta_path, META_TAG);
	strcat(meta_path, filename);
	return 0;
}

void init_meta_hash(Tracee *tracee) {
	char db_path[PATH_MAX];
	char *err = NULL;
	int status;

	status = translate_path(tracee, db_path, AT_FDCWD, DB_PATH, false); 
	if (status < 0)
		return;

	options = leveldb_options_create();
	leveldb_options_set_create_if_missing(options, 1);
	db = leveldb_open(options, db_path, &err);

	if (err != NULL) {
		VERBOSE(tracee, 2, "Failed to open Meta DB: %s", err);
	} else {
		VERBOSE(tracee, 9, "Succeeded to open Meta DB.");
	}

	/* reset error var */
	leveldb_free(err); err = NULL;

	woptions = leveldb_writeoptions_create();
	roptions = leveldb_readoptions_create();
}

/** Stores in mode, owner, and group the relative information found in the meta
 *  info. If the meta info doesn't exist, it reverts back to the original
 *  functionality of PRoot, with the addition of setting the mode to 755.
 */

int read_meta_info(char path[PATH_MAX], mode_t *mode, uid_t *owner, gid_t *group, Config *config)
{
	FILE *fp;
	int lcl_mode;
	int status;
	char meta_path[PATH_MAX];
	struct stat statBuf;
	size_t read_len;
	struct stat *hash_read_value;
	char* err = NULL;
	ino_t addr;
	Tracee *tracee = NULL;

	status = lstat(path, &statBuf);

	addr = statBuf.st_ino;
	if ((status == 0) && (addr > 0)) {
		hash_read_value = (struct stat *)leveldb_get(db, roptions, (char *)&addr, sizeof(ino_t), &read_len, &err);

		if (err != NULL) {
			read_len = 0;
			VERBOSE(tracee, 2, "Meta DB read failed: %s", err);
		}

		leveldb_free(err); err = NULL;
	}

        if ((status == 0) && (read_len > 0) && (addr > 0)) {
		*mode = hash_read_value->st_mode;
		*owner = hash_read_value->st_uid;
		*group = hash_read_value->st_gid;
		return 0;
	}

	status = get_meta_path(path, meta_path);
	fp = fopen(meta_path, "r");
	if(!fp || (status < 0)) {
		/* If the metafile doesn't exist, allow overly permissive behavior. */
		*owner = config->euid;
		*group = config->egid;
		*mode = otod(777);
		return 0;
	}
	fscanf(fp, "%d %d %d ", &lcl_mode, owner, group);
	*mode = otod(lcl_mode);
	write_meta_info(path, *mode, *owner, *group, false, config);
	unlink(meta_path);
	fclose(fp);

	return 0;
}

/** Writes mode, owner, and group to the meta info specified by path. If 
 *  is_creat is set to true, the umask needs to be used since it would have
 *  been by a real system call.
 */
int write_meta_info(char path[PATH_MAX], mode_t mode, uid_t owner, gid_t group,
	bool is_creat, Config *config)
{
	struct stat statBuf;
	int status;
	struct stat *ht_value;
	char* err = NULL;
	ino_t addr;
	Tracee *tracee = NULL;

	/** In syscalls that don't have the ability to create a file (chmod v open)
	 *  for example, the umask isn't used in determining the permissions of the
	 *  the file.
	 */
	if(is_creat)
		mode = (mode & ~(config->umask) & 0777);

	status = lstat(path, &statBuf);
	addr = statBuf.st_ino;

	if ((status == 0) && (addr > 0)) {
        	ht_value = malloc(sizeof(struct stat));
        	ht_value->st_mode = mode;
        	ht_value->st_uid = owner;
        	ht_value->st_gid = group;
		leveldb_put(db, woptions, (char *)&addr, sizeof(ino_t), (char *)ht_value, sizeof(struct stat), &err);
		if (err != NULL) {
			VERBOSE(tracee, 2, "Meta DB write failed: %s", err);
		}
		leveldb_free(err); err = NULL;
	}

	return 0;
}

/*
 * Deletes meta info based on path
 */
int delete_meta_info(char path[PATH_MAX]) {
	int status;
	char meta_path[PATH_MAX];
	char* err = NULL;
	Tracee *tracee = NULL;
	struct stat statBuf;
	ino_t addr;

	status = stat(path, &statBuf);
	addr = statBuf.st_ino;

	if ((status == 0) && (addr > 0)) {
		leveldb_delete(db, woptions, (char *)&addr, sizeof(ino_t), &err);
		if (err != NULL) {
			VERBOSE(tracee, 2, "Meta DB delete failed.");
		}
		leveldb_free(err); err = NULL;
	}

	status = get_meta_path(path, meta_path);
	if(status < 0)
		return 0;

	/* If metafile exists, delete it */
	if(path_exists(meta_path))
		unlink(meta_path);

	return 0;
}

void modify_pid_status_files(Tracee *tracee, Config *config, char translated_path[PATH_MAX]) {
	char new_path[PATH_MAX];
	char new_translated_path[PATH_MAX];
	char dir_path[PATH_MAX];
	char dir_path_translated[PATH_MAX];
	char *str, *s;
	struct stat statBuf;
	FILE *fp_in, *fp_out;
	char *line = NULL;
	size_t len = 0;
	ssize_t read;

	/* Make sure this is a system call and file of interest */
	word_t sysnum = get_sysnum(tracee, ORIGINAL);
	if ((sysnum != PR_open) && (sysnum != PR_openat))
		return;

	if (strncmp(translated_path, "/proc", 5) != 0)
		return;

	if (strlen(translated_path) < 7)
		return;

	if (strcmp(translated_path + strlen(translated_path) - 7, "/status") != 0)
		return;

	strcpy(new_path, "/support");
	strcat(new_path, translated_path);

	/* Create directory and copy file to new location */
	get_dir_path(new_path, dir_path);
	s = dir_path;
	while ((str = strtok(s, "/")) != NULL) {
		if (str != s) {
			str[-1] = '/';
		}
		if (stat (dir_path, &statBuf) == -1) {
			translate_path(tracee, dir_path_translated, AT_FDCWD, dir_path, true);
			mkdir (dir_path_translated, 0700);
		} else {
			return;
		}
		s = NULL;
	}

	translate_path(tracee, new_translated_path, AT_FDCWD, new_path, true);

	fp_in = fopen(translated_path, "r");
	if (fp_in == NULL) {
		return;
	}

	fp_out = fopen(new_translated_path, "w");
	if (fp_out == NULL) {
		return;
	}

	while ((read = getline(&line, &len, fp_in)) != -1) {
		if (strncmp(line, "Uid:", 4) == 0) {
			fprintf(fp_out, "Uid:   %d   %d   %d   %d\n", config->euid, config->euid, config->euid, config->euid);
		} else if (strncmp(line, "Gid:", 4) == 0) {
			fprintf(fp_out, "Gid:   %d   %d   %d   %d\n", config->egid, config->egid, config->egid, config->egid);
		} else {
			fprintf(fp_out, "%s", line);
		}
	}

	fclose(fp_in);
	fclose(fp_out);
	if (line)
		free(line);

	/* Change path to point at the new file */
	strcpy(translated_path, new_translated_path);
	return;
}
