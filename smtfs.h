#ifndef SMTFS_H
#define SMTFS_H

#define _GNU_SOURCE
#define FUSE_USE_VERSION FUSE_MAKE_VERSION(3, 18)

#include "khash.h"
#include "ksort.h"
#include <fuse3/fuse_lowlevel.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

#define MAX_FILES 1000000  //max files for an smtfs instance
#define DIRSPLIT 10000     //split files into subdirectories with DIRSPLIT files each on disk
#define MAX_DIRSIZE 10000  //max files to load into cache preemptively per directory
#define MAX_OPEN 50        //max cached directories
#define REFRESH_PERIOD 300 //cache refresh period

//flags for set_file_xattr
#define ADD 1 //add xattr
#define RMV 0 //remove xattr

//flags for remove_opendir and remove_openfile
#define RUNNING 1 //files flushed while system is running
#define STOP 0    //files flushed during shutdown process

//system directories
#define ROOT 1
#define ROOT_FN "/"
#define TAGS 2
#define TAGS_FN "_TAGS"
#define FILES 3
#define FILES_FN "_FILES"
#define HOME 4
#define HOME_FN "_Home"
#define SYSDIR 4

//error codes
#define DIRCONTERR 1
#define SETNAMEXATTRERR 2
#define SETNLINKXATTRERR 3
#define TIMESETERR 4
#define DIRINOERR 5
#define FREEMAPERR 6

#define min(x, y) ((x) < (y) ? (x) : (y))
#define max(x, y) ((x) > (y) ? (x) : (y))

//configuration passed from mount arguments to smt_init
struct fuse_smt_userdata {
    int refresh;       //unused
    int passthrough;   //-p option
    int dump;          //--dump option
    char *clear;       //-o clear= option
    char *import;      //-o import= option
    char *devfile;     //path of mountpoint
    int root_fd;       //file descriptor of mountpoint, for smt_statfs
    dev_t dev;         //dev of mountpoint
    blksize_t blksize; //blksize of mountpoint
    char *storage;     //root of storage
    char *backup;      //root of backup
};

//global configuration, set in smt_init
struct smtfs_config {
    int passthrough;   //-p option
    char *devfile;     //path of mountpoint
    int root_fd;       //file descriptor of mountpoint, for smt_statfs
    dev_t dev;         //dev of mountpoint
    blksize_t blksize; //blksize of mountpoint
    char *storage;     //root of storage
    char *backup;      //root of backup
    long int used;     //used inode count
    long int errcount; //error count since mounting
    char *errpath;     //directory for error logging
};

extern struct smtfs_config config; //in smtfs_fuse.h

//freemap
struct freeino {
    ino_t ino;              //free inode
    struct freeino *nextfr; //next free inode
};

extern struct freeino *freemap; //in smtfs_data.h

//struct for dirhash
struct dirinfo {
    ino_t ino;
    char *name;
};

//directory name->ino hashmap
KHASH_MAP_INIT_STR(dirhash, struct dirinfo*)
extern khash_t(dirhash) *dirh; //in smtfs_data.h

//dynamic inode array
struct inoarr {
    ino_t *inos; //inode array
    int size;    //number of inodes
    int exp;     //exponent of 2 for array resizing
};

//file info
struct openfileinfo {
    ino_t ino;
    int fd;                 //file descriptor made upon file creation, for diagnostics
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
    struct inoarr *dirinos; //inodes of directories containing this file
    int nref;               //number of open file descriptors
    time_t visit;           //last lookup timestamp
};

//inode->file info hashmap
KHASH_MAP_INIT_INT(openfilehash, struct openfileinfo*)
extern khash_t(openfilehash) *fcache; //in smtfs_data.h

//directory entry
struct opendirentry {
    ino_t ino;
    char *name; //filename will be modified to be unique in directory if there are duplicates
};

//dynamic array of directory entries
struct strarr {
    struct opendirentry *entries;
    int size; //number of entries
    int exp;  //exponent of 2 for array resizing
};

//directory info
struct opendirinfo {
    int openref;              //non-zero if there are open handles
    int index;                //index of own entry in visits
    struct inoarr *fileinos;  //inodes of contained files
    struct strarr *filenames; //filenames of contained files with modifications for duplicates
};

//inode->directory info hashmap
KHASH_MAP_INIT_INT(opendirhash, struct opendirinfo*)
extern khash_t(opendirhash) *opendirh; //in smtfs_data.h

//last visit timestamp for directory with inode ino
struct vst {
    time_t visit;
    ino_t ino;
};

//array of last visit timestamps for directories loaded into memory
struct last_visited {
    int currindex;      //first unused index
    struct vst *visits; //array of length MAX_OPEN
};

extern struct last_visited lvisit; //in smtfs_data.h

//smtfs_data.c
int find_ino_pos(struct inoarr *inos, ino_t ino);
ino_t insert_ino(struct inoarr *inos, ino_t ino);
ino_t remove_ino(struct inoarr *inos, ino_t ino);

int find_fname_pos(struct strarr *entries, char *fname);
ino_t insert_fname(struct strarr *entries, char *fname, ino_t ino);
ino_t remove_fname(struct strarr *entries, char *fname);

struct dirinfo* add_directory(const char *name, ino_t ino);
void remove_directory(const char *name);

int add_filetodir(const char *dirname, ino_t fileino);
void remove_filefromdir(const char *dirname, ino_t fileino);

int add_sysdirs(const char *name, mode_t mode);

ino_t add_file(const char *name, mode_t mode, off_t size);
int remove_file(ino_t ino);
khint_t add_openfile(ino_t ino);
void remove_openfile(ino_t ino, int sys_running);

khint_t add_opendir(ino_t ino);
void remove_opendir(ino_t ino, int sys_running);

ino_t dirset(const char *name, const char *pos);

//smtfs_disk.c
char* get_ino_path(char *root, ino_t ino);       // "root/(ino/DIRSPLIT)/ino"
char* get_file_path(char *root, char *filename); // "root/filename"
char* get_contents_path(char *root, ino_t ino);  // "root/(ino/DIRSPLIT)/ino/contents.txt"

void create_backup(char *root);

void* get_xattr_from_file(ino_t ino, char *name);
void set_file_xattr(ino_t ino, const char *tag, int mode);

int open_file(ino_t ino, const char *name, mode_t mode);
void set_file_attributes(struct openfileinfo *f);
void delete_file_on_disk(ino_t ino, mode_t mode);

void create_symlink(ino_t ino, char *name, char *target);
void rename_symlink(ino_t ino, char *newname);

int write_dirinos_into_file(char *root, char *filename);
int write_freemap_into_file(char *root, char *filename);
int write_dir_contents(ino_t dirino, struct inoarr *fileinos, int errnum);
int append_dir_contents(ino_t dirino, ino_t fileino);

void remove_xattr_from_dir(char *dirpath);
void export_metadata_txt(char *devpath, char *storagepath);

void write_error_file(ino_t ino, int errtype, void *data);

//smtfs_fuse.c
void fatal_error(const char *message);

void refreshdir(ino_t ino);

//smtfs_refresh.c
void* refresh_cache(void* arg);

//cp.c
int cp(const char *to, const char *from);

#endif
