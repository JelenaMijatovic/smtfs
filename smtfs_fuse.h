#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/sysmacros.h>

//filename->inode linked list hashmap used in refreshdir to keep track of duplicates
KHASH_MAP_INIT_STR(filenamehash, struct freeino*)

//directory entry buffer for smt_readdir
struct dirbuf {
	char *p;
	off_t size;
};

struct smtfs_config config; //global configuration

pthread_t refresh_thread; //runs smtfs_refresh.c

static void smt_destroy(void *userdata);
int recursive_dir(ino_t dirino, ino_t ino);
