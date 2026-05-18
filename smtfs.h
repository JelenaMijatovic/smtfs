#ifndef SMTFS_H
#define SMTFS_H

#define _GNU_SOURCE
#define FUSE_USE_VERSION FUSE_MAKE_VERSION(3, 18)

#include "klib/khash.h"
#include "klib/ksort.h"
#include <fuse3/fuse_lowlevel.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

#define MAX_FILES 1000000
#define MAX_DIRSIZE 100000
#define MAX_OPEN 50
#define MAX_FILENAME 256
#define DIRSPLIT 10000

#define ADD 1
#define RMV 0

#define ROOT 1
#define ROOT_FN "/"
#define TAGS 2
#define TAGS_FN "_TAGS"
#define FILES 3
#define FILES_FN "_FILES"
#define HOME 4
#define HOME_FN "_Home"
#define SYSDIR 4

#define min(x, y) ((x) < (y) ? (x) : (y))
#define max(x, y) ((x) > (y) ? (x) : (y))

//configuration
struct fuse_smt_userdata {
    int refresh;
    int passthrough;
    int root_fd;
    dev_t dev;
    blksize_t blksize;
    char *import;
    char *storage;
    char *backup;
};

struct smtfs_config {
    int passthrough;
    int root_fd;
    dev_t dev;
    blksize_t blksize;
    char *storage;
    char *backup;
};

extern struct smtfs_config config;

//freemap
struct freeino {
    ino_t ino;
    struct freeino *nextfr;
};

extern struct freeino *freemap;

//file info structures
struct dirinfo {
    ino_t ino;
    char *name;
};

KHASH_MAP_INIT_STR(dirhash, struct dirinfo*)
extern khash_t(dirhash) *dirh;

struct inoarr {
    ino_t *inos;
    int size;
    int exp;
};

struct openfileinfo {
    ino_t ino;
    int fd;
    char *name;
    off_t size;
    mode_t mode;
    nlink_t nlink;
    uid_t uid;
    gid_t gid;
    blkcnt_t blocks;
    struct timespec atime;
    struct timespec mtime;
    struct timespec ctime;
    struct timespec btime;
    struct inoarr *dirinos;
    int nref;
};

KHASH_MAP_INIT_INT(openfilehash, struct openfileinfo*)
extern khash_t(openfilehash) *fcache;

struct opendirentry {
    ino_t ino;
    char *name;
};

struct strarr {
    struct opendirentry *entries;
    int size;
    int exp;
};

struct opendirinfo {
    int index;
    struct inoarr *fileinos;
    struct strarr *filenames;
};

KHASH_MAP_INIT_INT(opendirhash, struct opendirinfo*)
extern khash_t(opendirhash) *opendirh;

KHASH_MAP_INIT_STR(filenamehash, int)

//cache replacement
struct vst {
    long long visit;
    ino_t ino;
};

struct last_visited {
    int currindex;
    long long currvisit;
    struct vst *visits; //MAX_OPEN
};

extern struct last_visited lvisit;

//fuse
struct dirbuf {
	char *p;
	off_t size;
};

//smtfs_data.c
int find_ino_pos(struct inoarr *inos, ino_t ino);
ino_t insert_ino(struct inoarr *inos, ino_t ino);
ino_t remove_ino(struct inoarr *inos, ino_t ino);

int find_fname_pos(struct strarr *entries, char *fname);
ino_t insert_fname(struct strarr *entries, char *fname, ino_t ino);
ino_t remove_fname(struct strarr *entries, char *fname);

struct dirinfo* add_directory(ino_t ino, const char* name);
void remove_directory(const char *name);

int add_filetodir(const char *dirname, ino_t fileino);
void remove_filefromdir(const char *dirname, ino_t fileino);

int add_sysdirs(const char *name, mode_t mode);

ino_t add_file(off_t size, const char *name, mode_t mode);
void remove_file(ino_t ino);
khint_t add_openfile(ino_t ino);
void remove_openfile(ino_t ino);

khint_t add_opendir(ino_t ino);
void remove_opendir(ino_t ino);

ino_t dirset(const char* name, const char *pos);

//smtfs_disk.c
char* get_ino_path(char* root, ino_t ino); //storageroot/(ino/DIRSPLIT)/ino
char* get_file_path(char* root, char* filename); //storageroot/filename

void* get_xattr_from_file(ino_t ino, char* name);
void set_file_xattr(ino_t ino, const char *tag, int mode);

int open_file(ino_t ino, const char* name, mode_t mode);
void delete_file_on_disk(ino_t ino, mode_t mode);

void create_symlink(ino_t ino, char* name, char* target);
void rename_symlink(ino_t ino, char* newname);

void write_dir_contents(ino_t ino, struct opendirinfo *opendir);
void append_dir_contents(ino_t dirino, ino_t ino);

//smtfs_fuse.c
void fatal_error(const char *message);

void smtfs_setup();
void smtfs_load();

int is_import_new(char* importroot);
void read_importdir(char* path, DIR *imfd, ino_t parent, char* parentname);
void import_dir(char* importroot);
void add_import(char* importdir);
void refresh_importdir(char* path, ino_t parent, char* parentname);
void refresh_imports();

void refreshdir(fuse_req_t req, struct dirbuf *b, ino_t ino, int addbuff);

//cp.c
int cp(const char *to, const char *from);

#endif
