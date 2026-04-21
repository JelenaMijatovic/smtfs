#define _GNU_SOURCE
#define FUSE_USE_VERSION FUSE_MAKE_VERSION(3, 18)

#include <fuse3/fuse_lowlevel.h>
#include "klib/khash.h"
#include "klib/ksort.h"
#include "klib/kbtree.h"
#include "cp.c"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <time.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/xattr.h>
#include <limits.h>
#include <libgen.h>

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

char *devfile = NULL;

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

struct smtfs_config config;

struct freeino {
    ino_t ino;
    struct freeino *nextfr;
};

struct freeino *freemap;

struct dirinfo {
    ino_t ino;
    char *name;
};

KHASH_MAP_INIT_STR(dirhash, struct dirinfo*)
khash_t(dirhash) *dirh;

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
    ino_t *dirinos;
    int dirinosize;
    int dirinoexp;
    int nref;
};

int find_dirino_pos(struct openfileinfo *f, ino_t ino) {
    int l = 0;
    int r = f->dirinosize-1;
    int pos = 0;
    while (l <= r) {
        pos = l + (r-l)/2;
        if (f->dirinos[pos] < ino) {
            l = pos + 1;
        } else if (f->dirinos[pos] > ino) {
            r = pos - 1;
        } else {
            break;
        }
    }
    return pos;
}

int insert_dirino(struct openfileinfo *f, ino_t ino) {
    if (f->dirinosize == 0) {
        f->dirinos[0] = ino;
        f->dirinosize++;
        return ino;
    }
    int pos = find_dirino_pos(f, ino);
    if (f->dirinos[pos] != ino) {
        f->dirinosize++;
        if (f->dirinosize > f->dirinoexp) {
            f->dirinoexp *= 2;
            ino_t *dirinos = realloc(f->dirinos, sizeof(ino_t)*f->dirinoexp);
            if (dirinos) {
                memset(dirinos + f->dirinosize-1, 0x0, sizeof(ino_t)*(f->dirinoexp - f->dirinosize));
                f->dirinos = dirinos;
            } else {
                f->dirinoexp /= 2;
                f->dirinosize--;
                return 0;
            }
        }
        if (f->dirinos[pos] > ino) {
            memcpy(&f->dirinos[pos+1], &f->dirinos[pos], sizeof(ino_t)*(f->dirinosize - pos-1));
            f->dirinos[pos] = ino;
        } else {
            if (pos+2 < f->dirinoexp) {
                memcpy(&f->dirinos[pos+2], &f->dirinos[pos+1], sizeof(ino_t)*(f->dirinosize - pos-1));
            }
            f->dirinos[pos+1] = ino;
        }
    }
    return ino;
}

int remove_dirino(struct openfileinfo *f, ino_t ino) {
    if (f->dirinosize < 1) {
        return 0;
    }
    int pos = find_dirino_pos(f, ino);
    if (f->dirinos[pos] == ino) {
        f->dirinosize--;
        if (f->dirinosize < f->dirinoexp/2 && f->dirinoexp > 2) {
            f->dirinoexp /= 2;
            ino_t *dirinos = realloc(f->dirinos, sizeof(ino_t)*f->dirinoexp);
            if (dirinos) {
                f->dirinos = dirinos;
            } else {
                f->dirinosize++;
                f->dirinoexp *= 2;
                return 0;
            }
        }
        memcpy(&f->dirinos[pos], &f->dirinos[pos+1], sizeof(ino_t)*(f->dirinosize-pos));
        return ino;
    } else {
        return 0;
    }
}

KHASH_MAP_INIT_INT(openfilehash, struct openfileinfo*)
khash_t(openfilehash) *fcache;

struct opendirentry {
    ino_t ino;
    char *name;
};

#define ino_cmp(a, b) (a < b ? -1 : (a > b ? 1 : 0))
KBTREE_INIT(kbt_fileinos, ino_t, ino_cmp);
#define filename_cmp(a, b) (strcmp((a).name, (b).name))
KBTREE_INIT(kbt_fnames, struct opendirentry, filename_cmp)

struct opendirinfo {
    int index;
    kbtree_t(kbt_fileinos) *fileinos;
    kbtree_t(kbt_fnames) *fnames;
};

KHASH_MAP_INIT_INT(opendirhash, struct opendirinfo*)
khash_t(opendirhash) *opendirh;

KHASH_MAP_INIT_STR(filenamehash, int)

struct vst {
    long long visit;
    ino_t ino;
};

struct last_visited {
    int currindex;
    long long currvisit;
    struct vst *visits; //MAX_OPEN
};

#define vst_lt(a, b) ((a).visit < (b).visit)
KSORT_INIT(vst, struct vst, vst_lt);

struct last_visited lvisit;

struct dirbuf {
	char *p;
	off_t size;
};

khint_t add_opendir(ino_t ino);
void remove_opendir(ino_t ino);
khint_t add_openfile(ino_t ino);
void refreshdir(fuse_req_t req, struct dirbuf *b, ino_t ino, int addbuff);
void* get_xattr_from_file(ino_t ino, char* name);
void fatal_error(const char *message);

char* get_ino_path(char* root, ino_t ino) {
    char *filepath = malloc(PATH_MAX);
    if (filepath) {
        filepath[0] = '\0';
        strcat(filepath, root);
        int length = snprintf(NULL, 0, "/%ld", ino / DIRSPLIT);
        char *strino = malloc(length+1);
        sprintf(strino, "/%ld", ino / DIRSPLIT);
        strcat(filepath, strino);
        free(strino);
        length = snprintf(NULL, 0, "/%ld", ino);
        strino = malloc(length+1);
        sprintf(strino, "/%ld", ino);
        strcat(filepath, strino);
        free(strino);
    }
    return filepath;
}

char* get_file_path(char* root, char* filename) {
    char* filepath = malloc(strlen(root) + strlen(filename)+1);
    if (filepath) {
        filepath[0] = '\0';
        strcat(filepath, root);
        strcat(filepath, filename);
    }
    return filepath;
}

struct dirinfo* add_directory(ino_t ino, const char* name) {

    struct dirinfo *dir = NULL;
    khint_t k;
    int absent;

    k = kh_get(dirhash, dirh, name);
    if (k == kh_end(dirh)) {
        dir = malloc(sizeof(struct dirinfo));
        if (dir) {
            dir->ino = ino;
            dir->name = malloc(strlen(name)+1);
            strncpy(dir->name, name, strlen(name));
            dir->name[strlen(name)] = '\0';
            k = kh_put(dirhash, dirh, dir->name, &absent);
            kh_val(dirh, k) = dir;
        }
    } else {
        dir = kh_val(dirh, k);
    }

    return dir;
}

void set_file_xattr(ino_t ino, const char *tag, int mode) {

    char *filepath = get_ino_path(config.storage, ino);
    char *filename = malloc(PATH_MAX);

    if (filepath && filename) {
        filename[0] = '\0';
        strcat(filename, "user.smtfs.");
        int length = snprintf(NULL, 0, "%s", tag);
        char *strino = malloc(length+1);
        sprintf(strino, "%s", tag);
        strcat(filename, strino);
        free(strino);

        if (mode == ADD) {
            setxattr(filepath, filename, "", 0, 0);
        } else {
            removexattr(filepath, filename);
        }
        free(filename);
    }
    free(filepath);
}

int add_filetodir(const char *name, ino_t ino) {

    khint_t k;

    k = kh_get(dirhash, dirh, name);
    if (k != kh_end(dirh)) {
        struct dirinfo *dir = kh_val(dirh, k);

        k = add_opendir(dir->ino);
        struct opendirinfo *opendir = kh_val(opendirh, k);

		if (kb_size(opendir->fileinos) == MAX_DIRSIZE) {
            return ENOSPC;
        }

        //link directory and file both ways
        ino_t *i = kb_getp(kbt_fileinos, opendir->fileinos, &ino);
        if (!i) {
            kb_putp(kbt_fileinos, opendir->fileinos, &ino);

            k = kh_get(openfilehash, fcache, ino);
            if (k != kh_end(fcache)) {
                struct openfileinfo *f = kh_value(fcache, k);
                f->nref++;

                insert_dirino(f, dir->ino);
                f->nlink++;
                clock_gettime(CLOCK_REALTIME, &f->ctime);
                k = kh_get(openfilehash, fcache, dir->ino);
                if (k != kh_end(fcache)) {
                    struct openfileinfo *f1 = kh_value(fcache, k);
                    clock_gettime(CLOCK_REALTIME, &f1->ctime);
                    clock_gettime(CLOCK_REALTIME, &f1->mtime);
                }
            }

            k = kh_get(openfilehash, fcache, dir->ino);
            if (k != kh_end(fcache)) {
                struct openfileinfo *f1 = kh_value(fcache, k);
                set_file_xattr(ino, f1->name, ADD);
            }

            refreshdir(NULL, NULL, dir->ino, 0);
            return 0;
        } else {
            return EEXIST;
        }
    }

    return ENOENT;
}

void remove_filefromdir(const char *name, ino_t ino) {
    khint_t k;

    k = kh_get(dirhash, dirh, name);
    if (k != kh_end(dirh)) {
        struct dirinfo *dir = kh_val(dirh, k);

        k = add_opendir(dir->ino);
        struct opendirinfo *opendir = kh_val(opendirh, k);

        kb_delp(kbt_fileinos, opendir->fileinos, &ino);
        k = add_openfile(ino);
        if (k != kh_end(fcache)) {
            struct openfileinfo *f = kh_value(fcache, k);
            f->nref--;

            remove_dirino(f, dir->ino);
            f->nlink--;
            clock_gettime(CLOCK_REALTIME, &f->ctime);
            k = add_openfile(dir->ino);
            if (k != kh_end(fcache)) {
                struct openfileinfo *f1 = kh_value(fcache, k);
                clock_gettime(CLOCK_REALTIME, &f1->ctime);
                clock_gettime(CLOCK_REALTIME, &f1->mtime);
            }
        }

        k = add_openfile(dir->ino);
        if (k != kh_end(fcache)) {
            struct openfileinfo *f1 = kh_value(fcache, k);
            set_file_xattr(ino, f1->name, RMV);
        }

        refreshdir(NULL, NULL, dir->ino, 0);
    }
}

void remove_directory(const char *name) {
    khint_t k;
    kbitr_t itr;

    k = kh_get(dirhash, dirh, name);
    if (k != kh_end(dirh)) {
        struct dirinfo *dir = kh_val(dirh, k);

        k = add_opendir(dir->ino);
        struct opendirinfo *opendir = kh_val(opendirh, k);

        kb_itr_first(kbt_fileinos, opendir->fileinos, &itr);
        for (; kb_itr_valid(&itr); kb_itr_next(kbt_fileinos, opendir->fileinos, &itr)) {
            ino_t ino = kb_itr_key(ino_t, &itr);
            remove_filefromdir(name, ino);
        }

        remove_opendir(dir->ino);
        kh_del(dirhash, dirh, k);
        free(dir->name);
        free(dir);
    }
}

int open_file(ino_t ino, const char* name, mode_t mode) {
    int newfd = 0;
    char *filepath = get_ino_path(config.storage, ino);

    if (filepath) {
        if ((mode & S_IFMT) == S_IFDIR) {
            newfd = mkdir(filepath, mode);
            if (!newfd) {
                setxattr(filepath, "user.smtfs_m.name", name, strlen(name)+1, 0);
                nlink_t link = 2;
                setxattr(filepath, "user.smtfs_m.nlink", &link, sizeof(link), 0);
            }
        } else {
            newfd = open(filepath, O_WRONLY | O_CREAT, mode);
            if (newfd) {
                setxattr(filepath, "user.smtfs_m.name", name, strlen(name)+1, 0);
                nlink_t link = 1;
                setxattr(filepath, "user.smtfs_m.nlink", &link, sizeof(link), 0);
            }
        }
        free(filepath);
    }

    return newfd;
}

void create_symlink(ino_t ino, const char* name, char* target) {
    char *filepath = get_ino_path(config.storage, ino);

    if (filepath) {
        symlink(target, filepath);
        setxattr(filepath, "user.smtfs_m.ino", &ino, sizeof(ino), 0);
        setxattr(filepath, "user.smtfs_m.name", name, strlen(name)+1, 0);
        nlink_t link = 1;
        setxattr(filepath, "user.smtfs_m.nlink", &link, sizeof(link), 0);
        free(filepath);
    }
}

void rename_symlink(ino_t ino, char* newname) {
    char *filepath = get_ino_path(config.storage, ino);

    if (filepath) {
        struct stat stbuf;
        memset(&stbuf, 0, sizeof(stbuf));
        lstat(filepath, &stbuf);
        if ((stbuf.st_mode & S_IFMT) == S_IFLNK) {
            char *buf = malloc(stbuf.st_size+1);
            if (buf) {
                readlink(filepath, buf, stbuf.st_size);
                buf[stbuf.st_size] = '\0';
                char *dirpath = strdup(buf);
                char *p = strstr(dirpath, basename(buf));
                char *pp = p;
                while (p != NULL) {
                    pp = p;
                    p = strstr(p+1, basename(buf));
                }
                *pp = '\0';
                char *newpath = malloc(strlen(dirpath) + strlen(newname)+1);
                newpath[0] = '\0';
                strcat(newpath, dirpath);
                strcat(newpath, newname);

                rename(buf, newpath);
                unlink(filepath);
                create_symlink(ino, newname, newpath);

                free(dirpath);
                free(newpath);
            }
            free(buf);
        }
        free(filepath);
    }
}

static int add_sysdirs(const char *name, mode_t mode) {
    if (freemap->ino < MAX_FILES) {
        open_file(freemap->ino, name, mode);

        struct openfileinfo *f = malloc(sizeof(struct openfileinfo));
        if (f) {
            f->ino = freemap->ino;
            f->name = (char *)malloc(strlen(name)+1);
            if (f->name) {
                strncpy(f->name, name, strlen(name));
                f->name[strlen(name)] = '\0';
            } else {
                free(f);
                return 0;
            }
            f->uid = 0;
            f->gid = 0;
            f->size = config.blksize;
            f->blocks = config.blksize/512;
            f->mode = mode;
            if (freemap->ino == ROOT) {
                f->nlink = 2;
            } else {
                f->nlink = 1;
            }
            f->dirinos = malloc(sizeof(ino_t)*2);
            memset(f->dirinos, 0x0, sizeof(ino_t)*2);
            f->dirinosize = 0;
            f->dirinoexp = 2;
            clock_gettime(CLOCK_REALTIME, &f->atime);
            clock_gettime(CLOCK_REALTIME, &f->mtime);
            clock_gettime(CLOCK_REALTIME, &f->ctime);
            clock_gettime(CLOCK_REALTIME, &f->btime);
            f->nref = 0;

            int absent;
            khint_t k = kh_put(openfilehash, fcache, f->ino, &absent);
            kh_val(fcache, k) = f;

            struct dirinfo *ret = add_directory(freemap->ino, name);
            if (!ret) {
                free(f->name);
                if (f->dirinos) {
                    free(f->dirinos);
                }
                free(f);
                return 0;
            }

            ino_t ino = freemap->ino;
            if (freemap->nextfr) {
                struct freeino *t = freemap;
                freemap = freemap->nextfr;
                free(t);
            } else {
                ++freemap->ino;
            }

            return ino;
        }
    }
    return 0;
}

ino_t add_file(off_t size, const char *name, mode_t mode) {

    if (freemap->ino < MAX_FILES) {

        int fd = open_file(freemap->ino, name, mode);

        struct openfileinfo *f = malloc(sizeof(struct openfileinfo));
        if (f) {
            f->ino = freemap->ino;
            f->name = (char *)malloc(strlen(name)+1);
            if (f->name) {
                strncpy(f->name, name, strlen(name));
                f->name[strlen(name)] = '\0';
            } else {
                free(f);
                return 0;
            }
            f->fd = fd;
            f->uid = 0;
            f->gid = 0;
            f->size = size;
            f->blocks = config.blksize/512;
            f->mode = mode;
            if ((mode & S_IFMT) == S_IFDIR) {
                f->nlink = 1;
            } else {
                f->nlink = 0;
            }
            f->dirinos = malloc(sizeof(ino_t)*2);
            memset(f->dirinos, 0x0, sizeof(ino_t)*2);
            f->dirinosize = 0;
            f->dirinoexp = 2;
            f->nref = 0;

            clock_gettime(CLOCK_REALTIME, &f->atime);
            clock_gettime(CLOCK_REALTIME, &f->mtime);
            clock_gettime(CLOCK_REALTIME, &f->ctime);
            clock_gettime(CLOCK_REALTIME, &f->btime);

            int absent;
            khint_t k = kh_put(openfilehash, fcache, f->ino, &absent);
            kh_val(fcache, k) = f;

            if ((mode & S_IFMT) == S_IFDIR) {
                struct dirinfo *ret = add_directory(freemap->ino, name);
                if (!ret || add_filetodir(TAGS_FN, freemap->ino)) { //_TAGS contains all directories except those in root
                    if (ret) {
                        remove_directory(name);
                    }
                    free(f->name);
                    if (f->dirinos) {
                        free(f->dirinos);
                    }
                    free(f);
                    return 0;
                }
            } else {
                if (add_filetodir(FILES_FN, freemap->ino)) { //_FILES contains all regular files
                    free(f->name);
                    if (f->dirinos) {
                        free(f->dirinos);
                    }
                    free(f);
                    return 0;
                }
            }

            ino_t ino = freemap->ino;
            if (freemap->nextfr) {
                struct freeino *t = freemap;
                freemap = freemap->nextfr;
                free(t);
            } else {
                ++freemap->ino;
            }

            return ino;
        }
    }
    return 0;
}

void delete_file_on_disk(ino_t ino, mode_t mode) {
    char *filepath = get_ino_path(config.storage, ino);

    if (filepath) {
        struct stat stbuf;
        memset(&stbuf, 0, sizeof(stbuf));
        lstat(filepath, &stbuf);
        if (config.passthrough) { //delete file in source dir
            char *buf = malloc(stbuf.st_size+1);
            if (buf) {
                readlink(filepath, buf, stbuf.st_size);
                buf[stbuf.st_size] = '\0';
                unlink(buf);
                free(buf);
            }
        } else if ((stbuf.st_mode & S_IFMT) == S_IFLNK) { //mark file in source dir as excluded
            ino = 0;
            setxattr(filepath, "user.smtfs_m.ino", &ino, sizeof(ino), 0);
        }

        remove(filepath); //remove from storage

        free(filepath);
    }
}

void remove_file(ino_t ino) {
    khint_t k, k1;

    k = add_openfile(ino);
    if (k != kh_end(fcache)) {
        struct openfileinfo *f = kh_value(fcache, k);
        while (f->dirinosize) {
            k1 = add_openfile(f->dirinos[0]);
            if (k1 != kh_end(fcache)) {
                struct openfileinfo *f1 = kh_value(fcache, k1);
                remove_filefromdir(f1->name, ino);
            }
        }

        mode_t mode = f->mode;
        if ((f->mode & S_IFMT) == S_IFDIR) {
            f->nlink--;
            remove_directory(f->name);
        }

        delete_file_on_disk(ino, mode);

        if ((mode & S_IFMT) != S_IFDIR) {
            free(f->name);
            if (f->dirinos) {
                free(f->dirinos);
            }
            free(f);
            kh_del(openfilehash, fcache, k);
        }
    }

    struct freeino *newino = calloc(1, sizeof(struct freeino));
    newino->ino = ino;
    if (ino < freemap->ino) {
        newino->nextfr = freemap;
        freemap = newino;
    } else {
        struct freeino *curr = freemap;
        while (curr->nextfr && curr->nextfr->ino > ino) {
            curr = curr->nextfr;
        }
        newino->nextfr = curr->nextfr;
        curr->nextfr = newino;
    }
}

void write_dir_contents(ino_t ino, struct opendirinfo *opendir) {
    kbitr_t itr;
    char *filepath = get_ino_path(config.storage, ino);

    if (filepath) {
        strcat(filepath, "/contents.txt");

        int newfd = open(filepath, O_WRONLY | O_APPEND | O_TRUNC | O_CREAT, 0777);
        if (newfd) {
            kb_itr_first(kbt_fileinos, opendir->fileinos, &itr);
            for (; kb_itr_valid(&itr); kb_itr_next(kbt_fileinos, opendir->fileinos, &itr)) {
                ino_t ino = kb_itr_key(ino_t, &itr);
                int length = snprintf(NULL, 0, "%ld\n", ino);
                char *strino = malloc(length+1);
                sprintf(strino, "%ld\n", ino);
                write(newfd, strino, length);
                free(strino);
            }
            close(newfd);
        } else {
            printf("write_dir_contents: Couldn't write to contents.txt for dir %ld!\n", ino);
        }
        free(filepath);
    }
}

void append_dir_contents(ino_t dirino, ino_t ino) {
    char *filepath = get_ino_path(config.storage, dirino);

    if (filepath) {
        strcat(filepath, "/contents.txt");

        int newfd = open(filepath, O_WRONLY | O_APPEND | O_CREAT, 0777);
        if (newfd) {
            int length = snprintf(NULL, 0, "%ld\n", ino);
            char *strino = malloc(length+1);
            sprintf(strino, "%ld\n", ino);
            write(newfd, strino, length);
            free(strino);
            close(newfd);
        } else {
            printf("append_dir_contents: Couldn't write to contents.txt for dir %ld!\n", dirino);
        }
        free(filepath);
    }
}

khint_t add_openfile(ino_t ino) {

    khint_t k = kh_get(openfilehash, fcache, ino);
    if (k != kh_end(fcache)) {
        return k;
    }

    k = kh_end(fcache);
    struct openfileinfo *f = malloc(sizeof(struct openfileinfo));
    f->ino = ino;
    f->fd = 0;

    f->name = (char *)get_xattr_from_file(ino, "user.smtfs_m.name");
    nlink_t *nlink = (nlink_t *)get_xattr_from_file(ino, "user.smtfs_m.nlink");
    if (nlink) {
        f->nlink = *nlink;
    } else {
        f->nlink = 2;
    }
    free(nlink);
    f->nref = 1;

    struct stat stbuf;
    struct statx stxbuf;
    memset(&stbuf, 0, sizeof(stbuf));
    memset(&stxbuf, 0, sizeof(stxbuf));
    int absent;
    char *filepath = get_ino_path(config.storage, ino);

    if (filepath) {
        stat(filepath, &stbuf);
        statx(0, filepath, 0, STATX_BTIME, &stxbuf);
        f->uid = stbuf.st_uid;
        f->gid = stbuf.st_gid;
        f->size = stbuf.st_size;
        f->blocks = stbuf.st_blocks;
        f->mode = stbuf.st_mode;
        f->atime = stbuf.st_atim;
        f->mtime = stbuf.st_mtim;
        f->ctime = stbuf.st_ctim;
        f->btime.tv_sec = stxbuf.stx_btime.tv_sec;
        f->btime.tv_nsec = stxbuf.stx_btime.tv_nsec;

        f->dirinos = malloc(sizeof(ino_t)*2);
        memset(f->dirinos, 0x0, sizeof(ino_t)*2);
        f->dirinosize = 0;
        f->dirinoexp = 2;

        int size = listxattr(filepath, 0, 0);
        if (size <= 0) {
            free(filepath);
            filepath = get_ino_path(config.backup, ino);
            size = listxattr(filepath, 0, 0);
        }
        if (size > 0) {
            char* list = malloc(size);
            if (list) {
                listxattr(filepath, list, size);
                int sum = 0;
                char *s = list;
                char *p;
                while (sum < size) {
                    sum += strlen(s)+1;
                    p = strstr(s, "user.smtfs.");
                    if (p) {
                        p = p + strlen("user.smtfs.");
                        khint_t k = kh_get(dirhash, dirh, p);
                        if (k != kh_end(dirh)) {
                            struct dirinfo *dir = kh_val(dirh, k);
                            insert_dirino(f, dir->ino);
                        }
                    }
                    s = strchr(s, '\0');
                    s++;
                }
            }
            free(list);
        }
        free(filepath);

        k = kh_put(openfilehash, fcache, f->ino, &absent);
        kh_val(fcache, k) = f;
    } else {
        free(f->name);
        free(f);
    }
    return k;
}

void remove_openfile(ino_t ino) {
    khint_t k = kh_get(openfilehash, fcache, ino);

    if (k != kh_end(fcache)) {
        struct openfileinfo *f = kh_val(fcache, k);
        f->nref--;
        if (!f->nref) {
            char *filepath = get_ino_path(config.storage, ino);
            if (filepath) {
                setxattr(filepath, "user.smtfs_m.name", f->name, strlen(f->name)+1, 0);
                setxattr(filepath, "user.smtfs_m.nlink", &f->nlink, sizeof(f->nlink), 0);
                struct timespec times[2];
                times[0].tv_sec = f->atime.tv_sec;
                times[0].tv_nsec = f->atime.tv_nsec;
                times[1].tv_sec = f->mtime.tv_sec;
                times[1].tv_nsec = f->mtime.tv_nsec;
                utimensat(AT_FDCWD, filepath, times, AT_SYMLINK_NOFOLLOW);

                free(filepath);
            }
            free(f->name);
            if (f->dirinos) {
                free(f->dirinos);
            }
            free(f);
            kh_del(openfilehash, fcache, k);
        }
    }
}

void remove_opendir(ino_t ino) {
    khint_t k;
    kbitr_t itr;

    k = kh_get(opendirhash, opendirh, ino);
    if (k != kh_end(opendirh)) {
        struct opendirinfo *opendir = kh_val(opendirh, k);
        lvisit.currindex = opendir->index;

        write_dir_contents(ino, opendir);

        kb_itr_first(kbt_fileinos, opendir->fileinos, &itr);
        for (; kb_itr_valid(&itr); kb_itr_next(kbt_fileinos, opendir->fileinos, &itr)) {
            ino_t ino = kb_itr_key(ino_t, &itr);
            remove_openfile(ino);
        }
        remove_openfile(ino);

        kb_itr_first(kbt_fnames, opendir->fnames, &itr);
        for (; kb_itr_valid(&itr); kb_itr_next(kbt_fnames, opendir->fnames, &itr)) {
            struct opendirentry *e = &kb_itr_key(struct opendirentry, &itr);
            free(e->name);
        }
        kb_destroy(kbt_fileinos, opendir->fileinos);
        kb_destroy(kbt_fnames, opendir->fnames);

        free(opendir);
        kh_del(opendirhash, opendirh, ino);
    }
}

khint_t add_opendir(ino_t ino) {

    khint_t k;
    int absent;

    k = kh_get(openfilehash, fcache, ino);
    if (k == kh_end(fcache)) {
        k = add_openfile(ino);
    }
    if (k != kh_end(fcache)) {
        struct openfileinfo *f = kh_value(fcache, k);
        if ((f->mode & S_IFMT) == S_IFDIR) {
            k = kh_get(opendirhash, opendirh, ino);
            if (k == kh_end(opendirh)) {
                if (kh_size(opendirh) >= MAX_OPEN) {
                    struct vst *visits = lvisit.visits;
                    struct vst t = ks_ksmall(vst, MAX_OPEN, visits, 0);
                    if (t.ino == ROOT) {
                        t = ks_ksmall(vst, MAX_OPEN, visits, 1);
                    }
                    remove_opendir(t.ino);
                }
                struct opendirinfo *dir = malloc(sizeof(struct opendirinfo));
                if (dir) {
                    dir->index = lvisit.currindex++;
                    lvisit.visits[dir->index].visit = lvisit.currvisit++;
                    lvisit.visits[dir->index].ino = ino;
                    dir->fileinos = kb_init(kbt_fileinos, KB_DEFAULT_SIZE);
                    dir->fnames = kb_init(kbt_fnames, KB_DEFAULT_SIZE);
                    ++f->nref;

                    //load directory contents
                    char *filepath = get_ino_path(config.storage, ino);
                    if (filepath) {
                        strcat(filepath, "/contents.txt");

                        FILE *fptr;
                        fptr = fopen(filepath, "r");
                        free(filepath);
                        if (fptr) {
                            ino_t fino;
                            while (fscanf(fptr, "%lu\n", &fino) != EOF) {
                                ino_t *t = kb_getp(kbt_fileinos, dir->fileinos, &fino);
                                if (!t) {
                                    kb_putp(kbt_fileinos, dir->fileinos, &fino);
                                }
                            }
                            fclose(fptr);
                        }
                    } else {
                        fatal_error("add_opendir: Couldn't allocate memory\n");
                    }
                    if (ino != FILES && ino != TAGS) { //!loading files for these two would be like loading in the entire FS
                        kbitr_t itr;
                        khint_t k;
                        ino_t fino;
                        kb_itr_first(kbt_fileinos, dir->fileinos, &itr);
                        for (; kb_itr_valid(&itr); kb_itr_next(kbt_fileinos, dir->fileinos, &itr)) {
                            fino = kb_itr_key(ino_t, &itr);
                            k = kh_get(openfilehash, fcache, fino);
                            if (k == kh_end(fcache)) {
                                add_openfile(fino);
                            } else {
                                struct openfileinfo *f = kh_value(fcache, k);
                                f->nref++;
                            }
                        }
                    }

                    k = kh_put(opendirhash, opendirh, ino, &absent);
                    kh_val(opendirh, k) = dir;
                    return k;
                }
            } else {
                return k;
            }
        }
    }

    return kh_end(opendirh);
}

static void smt_destroy(void *userdata);

void fatal_error(const char *message) {
    puts(message);
    smt_destroy(NULL);
    exit(1);
}

void smtfs_setup() {

    freemap = malloc(sizeof(struct freeino));
    freemap->ino = 1; //init to 1
    freemap->nextfr = NULL;

    for (int i = 0; i <= 99; i++) {
        char *filepath = malloc(PATH_MAX);
        if (filepath) {
            filepath[0] = '\0';
            strcat(filepath, config.storage);
            int length = snprintf(NULL, 0, "/%d", i);
            char *strino = malloc(length+1);
            sprintf(strino, "/%d", i);
            strcat(filepath, strino);
            free(strino);
            mkdir(filepath, 0700);
        }
        free(filepath);
    }

    char *root = strdup("/");
    add_sysdirs(root, S_IFDIR | 0777);

    char *tags = strdup(TAGS_FN);
    add_sysdirs(tags, S_IFDIR | 0777);
    add_filetodir(root, TAGS);
    free(tags);
    char *files = strdup(FILES_FN);
    add_sysdirs(files, S_IFDIR | 0777);
    add_filetodir(root, FILES);
    free(files);
    char *home = strdup("_Home");
    add_sysdirs(home, S_IFDIR | 0777);
    add_filetodir(root, HOME);
    free(home);
    free(root);
}

void* get_xattr_from_file(ino_t ino, char* name) {
    char *buf = NULL;
    char *path = get_ino_path(config.storage, ino);

    if (path) {
        int size = getxattr(path, name, 0, 0);
        if (size > 0) {
            buf = malloc(size);
            getxattr(path, name, buf, size);
        }
        free(path);
    }
    return buf;
}

void smtfs_load() {
    khint_t k;
    int absent;

    char* path = get_file_path(config.storage, "/OK");
    if (path) { //remove status file from last shutdown
        remove(path);
        free(path);
    }

    path = get_file_path(config.storage, "/free.txt");
    if (path) {
        FILE *fptr;
        fptr = fopen(path, "r");
        if (fptr) {
            ino_t ino;
            struct freeino *prev = malloc(sizeof(struct freeino));
            fscanf(fptr, "%lu\n", &prev->ino); //first inode guaranteed
            freemap = prev;
            struct freeino *curr = NULL;

            while (fscanf(fptr, "%lu\n", &ino) != EOF) {
                curr = malloc(sizeof(struct freeino));
                curr->ino = ino;
                prev->nextfr = curr;
                prev = curr;
            }
            prev->nextfr = NULL;

            fclose(fptr);
        } else {
            fatal_error("smtfs_load: Couldn't read free.txt!");
        }
        free(path);
    } else {
        fatal_error("smtfs_load: Couldn't allocate memory");
    }

    path = get_file_path(config.storage, "/dirs.txt");
    if (path) {
        FILE *fptr;
        fptr = fopen(path, "r");
        if (fptr) {
            ino_t ino;

            while (fscanf(fptr, "%lu\n", &ino) != EOF) {
                struct dirinfo *dir = malloc(sizeof(struct dirinfo));
                dir->ino = ino;
                dir->name = get_xattr_from_file(ino, "user.smtfs_m.name");
                k = kh_put(dirhash, dirh, dir->name, &absent);
                kh_val(dirh, k) = dir;
            }

            fclose(fptr);
        } else {
            fatal_error("smtfs_load: Couldn't read dirs.txt!");
        }
        free(path);
    } else {
        fatal_error("smtfs_load: Couldn't allocate memory");
    }
}

int is_import_new(char* importroot) {
    char* path = get_file_path(config.storage, "/imports.txt");
    if (path) {
        FILE *fptr;
        fptr = fopen(path, "r");
        free(path);
        if (fptr) {
            char *importdir = malloc(PATH_MAX);
            if (importdir) {
                while (fgets(importdir, PATH_MAX, fptr) != NULL) {
                    char *p = strchr(importdir, '\n');
                    *p = '\0';
                    if (!strncmp(importroot, importdir, strlen(importdir))) {
                        free(importdir);
                        fclose(fptr);
                        return 0;
                    }
                    memset(importdir, 0, PATH_MAX);
                }
                free(importdir);
            } else {
                fatal_error("is_import_new: Couldn't allocate memory");
            }
            fclose(fptr);
            return 1;
        } else { //imports.txt not found, first import
            return 1;
        }
    } else {
        fatal_error("is_import_new: Couldn't allocate memory");
    }
    return 0;
}

void read_importdir(char* path, DIR *imfd, ino_t parent, char* parentname) {
    struct dirent *entry = NULL;
    struct stat stbuf;
    memset(&stbuf, 0, sizeof(stbuf));
    while ((entry = readdir(imfd)) != NULL) {
        char *entrpath = malloc(PATH_MAX);
        if (entrpath) {
            entrpath[0] = '\0';
            strcat(entrpath, path);

            strcat(entrpath, "/");
            strcat(entrpath, entry->d_name);

            stat(path, &stbuf);
            if (strncmp(entry->d_name, ".", strlen(entry->d_name)) && strncmp(entry->d_name, "..", strlen(entry->d_name))) {
                ino_t ino;
                if (entry->d_type == DT_DIR) {
                    DIR *imfd = NULL;
                    imfd = opendir(entrpath);
                    if (imfd) {
                        khint_t k = kh_get(dirhash, dirh, entry->d_name);
                        if (k == kh_end(dirh)) {
                            if (freemap->nextfr) {
                                ino = freemap->ino;
                                struct freeino *temp = freemap;
                                freemap = freemap->nextfr;
                                free(temp);
                            } else {
                                ino = freemap->ino++;
                            }
                            add_directory(ino, entry->d_name);
                            open_file(ino, entry->d_name, 0777 | S_IFDIR);

                            append_dir_contents(TAGS, ino);
                            set_file_xattr(ino, TAGS_FN, ADD);
                        } else {
                            struct dirinfo *dir = kh_val(dirh, k);
                            ino = dir->ino;
                        }

                        read_importdir(entrpath, imfd, ino, entry->d_name);

                        closedir(imfd);
                    }
                } else {
                    if (freemap->nextfr) {
                        ino = freemap->ino;
                        struct freeino *temp = freemap;
                        freemap = freemap->nextfr;
                        free(temp);
                    } else {
                        ino = freemap->ino++;
                    }
                    create_symlink(ino, entry->d_name, entrpath);

                    append_dir_contents(FILES, ino);
                    set_file_xattr(ino, FILES_FN, ADD);
                }
                append_dir_contents(parent, ino);
                set_file_xattr(ino, parentname, ADD);
            }
            free(entrpath);
        }
    }
}

void import_dir(char* importroot) {

    char* path = malloc(PATH_MAX);
    if (path) {
        path[0] = '\0';
        strcat(path, importroot);

        struct stat stbuf;
        memset(&stbuf, 0, sizeof(stbuf));

        stat(importroot, &stbuf);
        if ((stbuf.st_mode & S_IFMT) == S_IFDIR) {
            DIR *imfd = opendir(importroot);
            if (imfd) {
                ino_t ino;
                char *importname = strdup(basename(importroot));
                khint_t k = kh_get(dirhash, dirh, importname);
                if (k == kh_end(dirh)) {
                    if (freemap->nextfr) {
                        ino = freemap->ino;
                        struct freeino *temp = freemap;
                        freemap = freemap->nextfr;
                        free(temp);
                    }
                    else {
                        ino = freemap->ino++;
                    }
                    add_directory(ino, importname);
                    open_file(ino, importname, 0777 | S_IFDIR);

                    append_dir_contents(TAGS, ino);
                    set_file_xattr(ino, TAGS_FN, ADD);
                } else {
                    struct dirinfo *dir = kh_val(dirh, k);
                    ino = dir->ino;
                }

                read_importdir(importroot, imfd, ino, importname);

                add_openfile(ino);
                add_filetodir(HOME_FN, ino);
                set_file_xattr(ino, HOME_FN, ADD);

                free(importname);
                closedir(imfd);
            } else {
               printf("import_dir: Couldn't open import directory, import aborted.");
            }
        } else {
            printf("import_dir: Import path isn't directory, import aborted.");
        }
        free(path);
    } else {
        printf("import_dir: Memory allocation fail, import aborted.");
    }
}

void add_import(char* importdir) {
    if (is_import_new(importdir)) {
        char* path = get_file_path(config.storage, "/imports.txt");
        if (path) {
            int fd = open(path, O_WRONLY | O_APPEND | O_CREAT, 0777);
            if (fd) {
                write(fd, importdir, strlen(importdir));
                write(fd, "\n", 1);
                close(fd);

                import_dir(importdir);
            } else {
                printf("add_import: Couldn't open imports.txt, skipping import\n");
            }
            free(path);
        } else {
            printf("add_import: Couldn't allocate memory during import, skipping\n");
        }
    } else {
        printf("add_import: Import directory %s already included, skipping\n", importdir);
    }
}

void refresh_importdir(char* path, ino_t parent, char* parentname) {
    DIR *imfd = opendir(path);
    if (imfd) {
        struct dirent *entry = NULL;
        struct stat stbuf;
        memset(&stbuf, 0, sizeof(stbuf));
        while ((entry = readdir(imfd)) != NULL) {
            char *entrpath = malloc(PATH_MAX);
            if (entrpath) {
                entrpath[0] = '\0';
                strcat(entrpath, path);

                strcat(entrpath, "/");
                strcat(entrpath, entry->d_name);

                stat(path, &stbuf);
                if (strncmp(entry->d_name, ".", strlen(entry->d_name)) && strncmp(entry->d_name, "..", strlen(entry->d_name))) {
                    ino_t ino;
                    if (entry->d_type == DT_DIR) {
                        DIR *imfd = NULL;
                        imfd = opendir(entrpath);
                        if (imfd) {
                            khint_t k = kh_get(dirhash, dirh, entry->d_name);
                            if (k == kh_end(dirh)) { //if new
                                if (freemap->nextfr) {
                                    ino = freemap->ino;
                                    struct freeino *temp = freemap;
                                    freemap = freemap->nextfr;
                                    free(temp);
                                } else {
                                    ino = freemap->ino++;
                                }
                                add_directory(ino, entry->d_name);
                                open_file(ino, entry->d_name, 0777 | S_IFDIR);

                                append_dir_contents(TAGS, ino);
                                set_file_xattr(ino, TAGS_FN, ADD);
                            } else {
                                struct dirinfo *dir = kh_val(dirh, k);
                                ino = dir->ino;
                            }

                            refresh_importdir(entrpath, ino, entry->d_name);

                            append_dir_contents(parent, ino);
                            set_file_xattr(ino, parentname, ADD);

                            closedir(imfd);
                        }
                    } else {
                        if (getxattr(entrpath, "user.smtfs_m.ino", &ino, sizeof(ino)) == -1) { //if new
                            if (freemap->nextfr) {
                                ino = freemap->ino;
                                struct freeino *temp = freemap;
                                freemap = freemap->nextfr;
                                free(temp);
                            } else {
                                ino = freemap->ino++;
                            }
                            create_symlink(ino, entry->d_name, entrpath);

                            append_dir_contents(FILES, ino);
                            set_file_xattr(ino, FILES_FN, ADD);
                            append_dir_contents(parent, ino);
                            set_file_xattr(ino, parentname, ADD);
                        } else if (ino != 0) { //if not excluded
                            char* stpath = get_ino_path(config.storage, ino);
                            if (stpath) {
                                struct stat stbuf;
                                memset(&stbuf, 0, sizeof(stbuf));
                                lstat(stpath, &stbuf);
                                if ((stbuf.st_mode & S_IFMT) == S_IFLNK) {
                                    unlink(stpath);
                                    create_symlink(ino, entry->d_name, entrpath);
                                }
                                free(stpath);
                            }
                        }
                    }
                }
                free(entrpath);
            }
        }
    }
    closedir(imfd);
}

void refresh_imports() {
    char* path = get_file_path(config.storage, "/imports.txt");
    if (path) {
        FILE *fptr;
        fptr = fopen(path, "r");
        free(path);
        if (fptr) {
            char *importdir = malloc(PATH_MAX);
            if (importdir) {
                while (fgets(importdir, PATH_MAX, fptr) != NULL) {
                    char *p = strchr(importdir, '\n');
                    *p = '\0';
                    printf("refreshing import dir %s...\n", importdir);

                    refresh_importdir(importdir, HOME, HOME_FN);

                    memset(importdir, 0, PATH_MAX);
                }
                free(importdir);
            } else {
                fatal_error("refresh_imports: Couldn't allocate memory");
            }
            fclose(fptr);
        } else {
            printf("refresh_imports: imports.txt not found\n");
        }
    } else {
        fatal_error("refresh_imports: Couldn't allocate memory");
    }
    for (int i = 0; i <= 99; i++) {
        char *filepath = malloc(PATH_MAX);
        if (filepath) {
            filepath[0] = '\0';
            strcat(filepath, config.storage);
            int length = snprintf(NULL, 0, "/%d", i);
            char *strino = malloc(length+1);
            sprintf(strino, "/%d", i);
            strcat(filepath, strino);
            free(strino);
            DIR *imfd = opendir(filepath);
            if (imfd) {
                struct dirent *entry = NULL;
                struct stat stbuf;
                memset(&stbuf, 0, sizeof(stbuf));
                while ((entry = readdir(imfd)) != NULL) {
                    if (strncmp(entry->d_name, ".", 1)) {
                        char *entrpath = malloc(PATH_MAX);
                        if (entrpath) {
                            entrpath[0] = '\0';
                            strcat(entrpath, filepath);

                            strcat(entrpath, "/");
                            strcat(entrpath, entry->d_name);

                            lstat(entrpath, &stbuf);
                            if ((stbuf.st_mode & S_IFMT) == S_IFLNK) {
                                char *buf = malloc(stbuf.st_size+1);
                                if (buf) {
                                    readlink(entrpath, buf, stbuf.st_size);
                                    buf[stbuf.st_size] = '\0';
                                    int fd = open(buf, O_RDONLY);
                                    if (fd == -1) {
                                        printf("Invalid link to import file: %s. Removing file entry %s...\n", buf, entry->d_name);

                                        ino_t ino;
                                        sscanf(entry->d_name, "%ld", &ino);

                                        remove_file(ino);

                                        khint_t k = kh_get(openfilehash, fcache, ino);
                                        if (k != kh_end(fcache)) {
                                            kh_del(openfilehash, fcache, k);
                                        }
                                    } else {
                                        close(fd);
                                    }
                                    free(buf);
                                }
                            }

                            memset(&stbuf, 0, sizeof(stbuf));
                            free(entrpath);
                        }
                    }
                }
                closedir(imfd);
            }
        }
        free(filepath);
    }
}

static void smt_init(void *userdata, struct fuse_conn_info *conn) {

    dirh = kh_init(dirhash);
    fcache = kh_init(openfilehash);
    opendirh = kh_init(opendirhash);
    lvisit.currindex = 0;
    lvisit.currvisit = 0;
    lvisit.visits = calloc(MAX_OPEN, sizeof(struct vst));
    if (!lvisit.visits) {
        fatal_error("Couldn't allocate last_visited!");
    }

    //load relevant runtime configuration
    struct fuse_smt_userdata *fuseconf = userdata;
    config.passthrough = fuseconf->passthrough;
    config.root_fd = fuseconf->root_fd;
    config.storage = fuseconf->storage;
    config.backup = fuseconf->backup;
    config.dev = fuseconf->dev;
    config.blksize = fuseconf->blksize;

    //test if storage is set up
    DIR *test_fd = NULL;
    char *path = get_file_path(config.storage, "/0");
    if (path) {
        test_fd = opendir(path);
        free(path);
    }

    if (test_fd) {
        smtfs_load();
    } else {
        smtfs_setup();
    }
    closedir(test_fd);

    if (fuseconf->refresh) {
        refresh_imports();
    }

    if (fuseconf->import) {
        char *importdir = fuseconf->import;
        if (strchr(fuseconf->import, '&')) {
            char *q = importdir;
            while ((q = strchr(q, '&'))) {
                *q = '\0';
                add_import(importdir);
                *q = '&';
                importdir = ++q;
            }
        }
        add_import(importdir);
    }

    add_opendir(ROOT);
    add_opendir(HOME);
    refreshdir(NULL, NULL, ROOT, 0);
}

void copy_to_backup(char* name) {
    char* backuppath = get_file_path(config.backup, name);
    char* ogpath = get_file_path(config.storage, name);
    if (backuppath && ogpath) {
        cp(backuppath, ogpath);
        free(backuppath);
        free(ogpath);
    }
}

static void smt_destroy(void *userdata) {

    printf("smt_destroy: Shutting down...\n");
    int ok = 1;

    for (khint_t k = 0; k < kh_end(opendirh); ++k)
        if (kh_exist(opendirh, k)) {
            remove_opendir(kh_key(opendirh, k));
        }
    kh_destroy(opendirhash, opendirh);
    free(lvisit.visits);

    char *filepath = get_file_path(config.storage, "/dirs.txt");
    if (filepath) {
        int newfd = open(filepath, O_WRONLY | O_TRUNC | O_CREAT, 0777);
        if (newfd) {
            char *strino;
            for (khint_t k = 0; k < kh_end(dirh); ++k)
                if (kh_exist(dirh, k)) {
                    struct dirinfo* dir = kh_val(dirh, k);
                    int length = snprintf(NULL, 0, "%ld\n", dir->ino);
                    strino = malloc(length+1);
                    sprintf(strino, "%ld\n", dir->ino);
                    write(newfd, strino, length);
                    free(strino);
                }
        } else {
            printf("smt_destroy: Couldn't write to dirs.txt!\n");
            ok = 0;
        }
        free(filepath);
        close(newfd);
    }

    for (khint_t k = 0; k < kh_end(dirh); ++k)
        if (kh_exist(dirh, k)) {
            struct dirinfo* dir = kh_val(dirh, k);
            free(dir->name);
            free(dir);
        }
    kh_destroy(dirhash, dirh);

    for (khint_t k = 0; k < kh_end(fcache); ++k)
        if (kh_exist(fcache, k)) {
            struct openfileinfo* f = kh_val(fcache, k);
            free(f->name);
            if (f->dirinos) {
                free(f->dirinos);
            }
            free(f);
        }
    kh_destroy(openfilehash, fcache);

    filepath = get_file_path(config.storage, "/free.txt");
    if (filepath) {
        int newfd = open(filepath, O_WRONLY | O_TRUNC | O_CREAT, 0777);
        if (newfd) {
            int length;
            char *strino;
            struct freeino *curr = freemap;
            struct freeino *temp;
            while (curr) {
                length = snprintf(NULL, 0, "%ld\n", curr->ino);
                strino = malloc(length+1);
                sprintf(strino, "%ld\n", curr->ino);
                write(newfd, strino, length);
                free(strino);
                temp = curr;
                curr = curr->nextfr;
                free(temp);
            }
        } else {
            printf("smt_destroy: Couldn't write to free.txt!\n");
            ok = 0;
        }
        free(filepath);
        close(newfd);
    }

    if (ok) {
        char* okpath = get_file_path(config.storage, "/OK");
        if (okpath) {
            int okfd = open(okpath, O_RDONLY | O_CREAT, 0777);
            if (okfd) { //smtfs healthy, ok to create backup

                copy_to_backup("/dirs.txt");
                copy_to_backup("/free.txt");
                copy_to_backup("/imports.txt");

                for (int i = 0; i <= 99; i++) {
                    filepath = malloc(PATH_MAX);
                    if (filepath) {
                        filepath[0] = '\0';
                        strcat(filepath, config.storage);
                        int length = snprintf(NULL, 0, "/%d", i);
                        char *strino = malloc(length+1);
                        sprintf(strino, "/%d", i);
                        strcat(filepath, strino);
                        DIR *imfd = opendir(filepath);
                        if (imfd) {
                            char *bdirpath = get_file_path(config.backup, strino);
                            if (bdirpath) {
                                mkdir(bdirpath, 0777);
                                DIR *bkfd = opendir(bdirpath);
                                struct dirent *entry = NULL;
                                while ((entry = readdir(bkfd)) != NULL) { //delete existing backup first
                                    if (strncmp(entry->d_name, ".", 1)) {
                                        ino_t ino;
                                        sscanf(entry->d_name, "%ld", &ino);
                                        char *entrpath = get_ino_path(config.backup, ino);
                                        if (entrpath) {
                                            remove(entrpath);
                                            free(entrpath);
                                        }
                                    }
                                }
                                closedir(bkfd);
                                free(bdirpath);
                            }
                            struct dirent *entry = NULL;
                            struct stat stbuf;
                            memset(&stbuf, 0, sizeof(stbuf));
                            while ((entry = readdir(imfd)) != NULL) {
                                if (strncmp(entry->d_name, ".", 1)) {
                                    ino_t ino;
                                    sscanf(entry->d_name, "%ld", &ino);
                                    char *entrpath = get_ino_path(config.storage, ino);
                                    char *backuppath = get_ino_path(config.backup, ino);
                                    if (entrpath && backuppath) {
                                        lstat(entrpath, &stbuf);
                                        if ((stbuf.st_mode & S_IFMT) == S_IFDIR) {
                                            mkdir(backuppath, 0777);

                                            char *contpathb = get_file_path(backuppath, "/contents.txt");
                                            char *contpaths = get_file_path(entrpath, "/contents.txt");
                                            if (contpathb && contpaths) {
                                                cp(contpathb, contpaths);
                                                free(contpathb);
                                                free(contpaths);
                                            }
                                        } else if ((stbuf.st_mode & S_IFMT) == S_IFLNK) {
                                            int fd = open(backuppath, O_WRONLY | O_TRUNC | O_CREAT, 0777);
                                            char *buf = malloc(stbuf.st_size + 1);
                                            readlink(entrpath, buf, stbuf.st_size);
                                            buf[stbuf.st_size] = '\0';
                                            write(fd, buf, stbuf.st_size);
                                            free(buf);
                                            close(fd);
                                        } else {
                                            int fd = open(backuppath, O_RDONLY | O_CREAT, 0777);
                                            close(fd);
                                        }

                                        int size = listxattr(entrpath, 0, 0);
                                        if (size > 0) {
                                            char* list = malloc(size);
                                            if (list) {
                                                listxattr(entrpath, list, size);
                                                int sum = 0;
                                                char *s = list;
                                                while (sum < size) {
                                                    sum += strlen(s)+1;
                                                    if (s) {
                                                        int psize = getxattr(entrpath, s, 0, 0);
                                                        char *buf = malloc(psize);
                                                        if (buf) {
                                                            getxattr(entrpath, s, buf, psize);
                                                            setxattr(backuppath, s, buf, psize, 0);
                                                            free(buf);
                                                        }
                                                    }
                                                    s = strchr(s, '\0');
                                                    s++;
                                                }
                                            }
                                            free(list);
                                        }

                                        memset(&stbuf, 0, sizeof(stbuf));
                                        free(entrpath);
                                        free(backuppath);
                                    }
                                }
                            }
                            closedir(imfd);
                        }
                        free(strino);
                        free(filepath);
                    }
                }

                close(okfd);
            } else {
                printf("smt_destroy: Couldn't create OK status file, backup will be skipped...\n");
            }
            free(okpath);
        }
    }

    printf("smt_destroy: Finished cleanup\n");
}

static void smt_access(fuse_req_t req, fuse_ino_t ino, int mask) {
    //struct stat stbuf;

        //stat(filepath, &stbuf);
        //stbuf.st_mode

    fuse_reply_err(req, ENOSYS);
}

static void dirbuf_add(fuse_req_t req, struct dirbuf *b, const char *name, fuse_ino_t ino)
{
	struct stat stbuf;
	off_t oldsize = b->size;

	b->size += fuse_add_direntry(req, NULL, 0, name, NULL, 0);
	b->p = (char *) realloc(b->p, b->size);
	memset(&stbuf, 0, sizeof(stbuf));
	stbuf.st_ino = ino;
	fuse_add_direntry(req, b->p + oldsize, b->size - oldsize, name, &stbuf, b->size);
}

void refreshdir(fuse_req_t req, struct dirbuf *b, ino_t ino, int addbuff) {

    struct openfileinfo *f = NULL;
    struct dirinfo *dir = NULL;
    khint_t k;
    k = kh_get(openfilehash, fcache, ino);
    if (k != kh_end(fcache)) {
        f = kh_val(fcache, k);
        k = kh_get(dirhash, dirh, f->name);
        if (k != kh_end(dirh)) {
            dir = kh_val(dirh, k);
        }
    }

    k = add_opendir(ino);

    if (k != kh_end(opendirh) && dir != NULL) {
        khash_t(filenamehash) *fnh = kh_init(filenamehash);
        khint_t k1;
        int absent;

        struct opendirinfo *opendir = kh_val(opendirh, k);
        lvisit.visits[opendir->index].visit = lvisit.currvisit++;
        kbitr_t itr;
        kb_itr_first(kbt_fnames, opendir->fnames, &itr);
        for (; kb_itr_valid(&itr); kb_itr_next(kbt_fnames, opendir->fnames, &itr)) {
            struct opendirentry *p = &kb_itr_key(struct opendirentry, &itr);
            free(p->name);
        }
        kb_destroy(kbt_fnames, opendir->fnames);
        opendir->fnames = kb_init(kbt_fnames, KB_DEFAULT_SIZE);

        kb_itr_first(kbt_fileinos, opendir->fileinos, &itr);
        for (; kb_itr_valid(&itr); kb_itr_next(kbt_fileinos, opendir->fileinos, &itr)) {
            ino_t ino = kb_itr_key(ino_t, &itr);

            k = kh_get(openfilehash, fcache, ino);
            if (k != kh_end(fcache)) {
                struct openfileinfo *f = kh_value(fcache, k);
                k1 = kh_get(filenamehash, fnh, f->name);
                if (k1 != kh_end(fnh)) {
                    kh_value(fnh, k1) = 1;
                } else {
                    k1 = kh_put(filenamehash, fnh, f->name, &absent);
                    kh_value(fnh, k1) = 0;
                }
            }
        }

        int p = 0;
        kb_itr_first(kbt_fileinos, opendir->fileinos, &itr);
        for (; kb_itr_valid(&itr); kb_itr_next(kbt_fileinos, opendir->fileinos, &itr)) {
            ino_t ino = kb_itr_key(ino_t, &itr);

            struct opendirentry *fin;
            k = kh_get(openfilehash, fcache, ino);
            if (k != kh_end(fcache)) {
                struct openfileinfo *f = kh_value(fcache, k);

                k1 = kh_get(filenamehash, fnh, f->name);
                if (kh_value(fnh, k1) == 1) {
                    char *name;
                    int length = snprintf(NULL, 0, "%ld", f->ino);
                    char app[length+1];
                    if ((name = malloc(strlen(f->name) + length + 2)) != NULL) {
                        name[0] = '\0';
                        sprintf(app, "%ld", f->ino);
                        strcat(name, f->name);
                        strcat(name, ":");
                        strcat(name, app);

                        fin = calloc(1, sizeof(struct opendirentry));
                        fin->ino = f->ino;
                        fin->name = (char*)malloc(MAXNAMLEN);
                        if (!fin->name) {
                            printf("refreshdir: filename malloc fail -> %ld\n", f->ino);
                            continue;
                        }
                        strncpy(fin->name, name, strlen(name));
                        fin->name[strlen(name)] = '\0';
                        kb_putp(kbt_fnames, opendir->fnames, fin);
                        free(name);
                    } else {
                        printf("refreshdir: filename malloc fail -> %ld\n", f->ino);
                        continue;
                    }
                } else {
                    fin = calloc(1, sizeof(struct opendirentry));
                    fin->ino = f->ino;
                    fin->name = (char*)malloc(MAXNAMLEN);
                    if (!fin->name) {
                        printf("refreshdir: filename malloc fail -> %ld\n", f->ino);
                        continue;
                    }
                    strncpy(fin->name, f->name, strlen(f->name));
                    fin->name[strlen(f->name)] = '\0';
                    kb_putp(kbt_fnames, opendir->fnames, fin);
                }

                if (addbuff) {
                    dirbuf_add(req, b, fin->name, fin->ino);
                }
                free(fin);
                p++;
            }
        }

        kh_destroy(filenamehash, fnh);
    }
}

static int reply_buf_limited(fuse_req_t req, const char *buf, size_t bufsize, off_t off, size_t maxsize) {
    if (off < maxsize) {
        return fuse_reply_buf(req, buf, min(bufsize, maxsize));
    } else {
        return fuse_reply_buf(req, NULL, 0);
    }
}

ino_t dirset(const char* name, const char *pos) {

    char *dir1 = (char *)malloc((pos-name)+1);
    strncpy(dir1, name, pos-name);
    dir1[pos-name] = '\0';
    char *dir2 = (char *)malloc(strlen(name)-(pos-name));
    strncpy(dir2, name+(pos-name)+2, strlen(name)-(pos-name)-1);
    dir2[strlen(name)-(pos-name)-1] = '\0';

    struct dirinfo *di1 = NULL;
    khint_t k = kh_get(dirhash, dirh, dir1);
    if (k != kh_end(dirh)) {
        di1 = kh_val(dirh, k);
    }
    struct dirinfo *di2 = NULL;
    k = kh_get(dirhash, dirh, dir2);
    if (k != kh_end(dirh)) {
        di2 = kh_val(dirh, k);
    }

    k = add_opendir(di1->ino);
    struct opendirinfo *d1 = kh_val(opendirh, k);
    k = add_opendir(di2->ino);
    struct opendirinfo *d2 = kh_val(opendirh, k);

    free(dir1);
    free(dir2);

    kbitr_t itr;
    if (d1 && d2) {
        switch (name[(pos-name)+1]) {
            case '&':{
                        ino_t ino = add_file(config.blksize, name, S_IFDIR | 0777);

                        kb_itr_first(kbt_fileinos, d1->fileinos, &itr);
                        for (; kb_itr_valid(&itr); kb_itr_next(kbt_fileinos, d1->fileinos, &itr)) {
                            ino_t i1 = kb_itr_key(ino_t, &itr);
                            ino_t *i2 = kb_getp(kbt_fileinos, d2->fileinos, &i1);
                            if (i2) {
                                add_filetodir(name, i1);
                            }
                        }

                        return ino;
                    }
            case '|':{
                        ino_t ino = add_file(config.blksize, name, S_IFDIR | 0777);

                        kb_itr_first(kbt_fileinos, d1->fileinos, &itr);
                        for (; kb_itr_valid(&itr); kb_itr_next(kbt_fileinos, d1->fileinos, &itr)) {
                            ino_t i1 = kb_itr_key(ino_t, &itr);
                            add_filetodir(name, i1);
                        }
                        kb_itr_first(kbt_fileinos, d2->fileinos, &itr);
                        for (; kb_itr_valid(&itr); kb_itr_next(kbt_fileinos, d2->fileinos, &itr)) {
                            ino_t i2 = kb_itr_key(ino_t, &itr);
                            add_filetodir(name, i2);
                        }

                        return ino;
                    }
            case '^':{
                        ino_t ino = add_file(config.blksize, name, S_IFDIR | 0777);

                        kb_itr_first(kbt_fileinos, d1->fileinos, &itr);
                        for (; kb_itr_valid(&itr); kb_itr_next(kbt_fileinos, d1->fileinos, &itr)) {
                            ino_t i1 = kb_itr_key(ino_t, &itr);
                            ino_t *i2 = kb_getp(kbt_fileinos, d2->fileinos, &i1);
                            if (!i2) {
                                add_filetodir(name, i1);
                            }
                        }
                        kb_itr_first(kbt_fileinos, d2->fileinos, &itr);
                        for (; kb_itr_valid(&itr); kb_itr_next(kbt_fileinos, d2->fileinos, &itr)) {
                            ino_t i2 = kb_itr_key(ino_t, &itr);
                            ino_t *i1 = kb_getp(kbt_fileinos, d1->fileinos, &i2);
                            if (!i1) {
                                add_filetodir(name, i2);
                            }
                        }

                        return ino;
                    }
            case '~':{
                        ino_t ino = add_file(config.blksize, name, S_IFDIR | 0777);

                        kb_itr_first(kbt_fileinos, d1->fileinos, &itr);
                        for (; kb_itr_valid(&itr); kb_itr_next(kbt_fileinos, d1->fileinos, &itr)) {
                            ino_t i1 = kb_itr_key(ino_t, &itr);
                            ino_t *i2 = kb_getp(kbt_fileinos, d2->fileinos, &i1);
                            if (!i2) {
                                add_filetodir(name, i1);
                            }
                        }

                        return ino;
                    }
            default: return 0;
        }
    }
    return 0;
}

static void smt_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
    struct fuse_entry_param e;
    khint_t k;
    struct openfileinfo *f = NULL;

    memset(&e, 0, sizeof(e));

    k = add_opendir(parent);

    if (k != kh_end(opendirh)) {
        struct opendirinfo *opendir = kh_val(opendirh, k);

        struct opendirentry *fin = calloc(1, sizeof(struct opendirentry));
        fin->name = (char*)malloc(strlen(name)+1);
        strncpy(fin->name, name, strlen(name));
        fin->name[strlen(name)] = '\0';
        struct opendirentry *entry = kb_getp(kbt_fnames, opendir->fnames, fin);
        if (entry) {
            k = kh_get(openfilehash, fcache, entry->ino);
            if (k != kh_end(fcache)) {
                f = kh_value(fcache, k);
            }
        }
        free(fin->name);
        free(fin);
    } else if (!strncmp("..", name, strlen(".."))) {
        k = kh_get(openfilehash, fcache, ROOT);
        if (k != kh_end(fcache)) {
            f = kh_value(fcache, k);
        }
    }

    if (f) {
        e.ino = f->ino;
        e.attr.st_ino = f->ino;
        e.attr.st_mode = f->mode;
        e.attr.st_nlink = f->nlink;
        e.attr.st_size = f->size;
        e.attr.st_atim = f->atime;
        e.attr.st_ctim = f->ctime;
        e.attr.st_mtim = f->mtime;
        e.attr_timeout = 1.0;
        e.entry_timeout = 10.0;

        if ((f->mode & S_IFMT) == S_IFDIR) {
            refreshdir(req, NULL, f->ino, 0);
        }

        fuse_reply_entry(req, &e);
        return;
    }
    fuse_reply_err(req, ENOENT);
}

static void smt_forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup) {

    khint_t k = kh_get(openfilehash, fcache, ino);
    if (k != kh_end(fcache)) {
        struct openfileinfo *f = kh_value(fcache, k);
        if (f->nlink == 0 || ((f->mode & S_IFMT) == S_IFDIR && f->nlink == 1)) { //check if nothing else links to the file
            remove_file(ino);
            fuse_reply_err(req, 0);
        } else {
            fuse_reply_err(req, EMLINK);
        }
    } else {
        fuse_reply_err(req, ENOENT);
    }
}

static void smt_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    struct stat stbuf;
    memset(&stbuf, 0, sizeof(stbuf));

    khint_t k = add_openfile(ino);
    if (k != kh_end(fcache)) {
        struct openfileinfo *f = kh_value(fcache, k);
        stbuf.st_dev = config.dev;
        stbuf.st_ino = ino;
        stbuf.st_mode = f->mode;
        stbuf.st_nlink = f->nlink;
        stbuf.st_uid = f->uid;
        stbuf.st_gid = f->gid;
        stbuf.st_size = f->size;
        stbuf.st_blksize = config.blksize;
        stbuf.st_blocks = f->blocks;
        stbuf.st_atim = f->atime;
        stbuf.st_ctim = f->ctime;
        stbuf.st_mtim = f->mtime;
        fuse_reply_attr(req, &stbuf, 1.0);
    } else {
        fuse_reply_err(req, ENOENT);
    }
}

static void smt_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr, int to_set, struct fuse_file_info *fi) {
    struct stat stbuf;
    memset(&stbuf, 0, sizeof(stbuf));

    khint_t k = add_openfile(ino);
    if (k != kh_end(fcache)) {
        struct openfileinfo *f = kh_value(fcache, k);

        stbuf.st_ino = f->ino;
        stbuf.st_nlink = f->nlink;

        if (to_set & FUSE_SET_ATTR_MODE) {
            f->mode = attr->st_mode;
        }
        stbuf.st_mode = f->mode;

        if (to_set & FUSE_SET_ATTR_UID) {
            f->uid = attr->st_uid;
        }
        stbuf.st_uid = f->uid;

        if (to_set & FUSE_SET_ATTR_GID) {
            f->gid = attr->st_gid;
        }
        stbuf.st_gid = f->gid;

        if (to_set & FUSE_SET_ATTR_SIZE) {
            f->size = attr->st_size;
        }
        stbuf.st_size = f->size;

        if (to_set & FUSE_SET_ATTR_ATIME) {
            f->atime = attr->st_atim;
        } else if (to_set & FUSE_SET_ATTR_ATIME_NOW) {
            f->atime.tv_nsec = UTIME_NOW;
        }
        stbuf.st_atim = f->atime;

        if (to_set & FUSE_SET_ATTR_MTIME) {
            f->mtime = attr->st_mtim;
        } else if (to_set & FUSE_SET_ATTR_MTIME_NOW) {
            f->mtime.tv_nsec = UTIME_NOW;
        }
        stbuf.st_mtim = f->mtime;

        if (to_set & FUSE_SET_ATTR_CTIME) {
            f->ctime = attr->st_ctim;
        }
        stbuf.st_ctim = f->ctime;

        fuse_reply_attr(req, &stbuf, 1.0);
    } else {
        fuse_reply_err(req, ENOENT);
    }
}

void smt_statx(fuse_req_t req, fuse_ino_t ino, int flags, int mask, struct fuse_file_info *fi) {
    struct statx stxbuf;
    memset(&stxbuf, 0, sizeof(stxbuf));

    khint_t k = add_openfile(ino);
    if (k != kh_end(fcache)) {
        struct openfileinfo *f = kh_value(fcache, k);
        stxbuf.stx_mask = STATX_BASIC_STATS | STATX_BTIME;
        stxbuf.stx_blksize = config.blksize;
        stxbuf.stx_nlink = f->nlink;
        stxbuf.stx_uid = f->uid;
        stxbuf.stx_gid = f->gid;
        stxbuf.stx_mode = f->mode;
        stxbuf.stx_ino = f->ino;
        stxbuf.stx_size = f->size;
        stxbuf.stx_blocks = f->blocks;
        stxbuf.stx_attributes_mask = 0x0;
        stxbuf.stx_atime.tv_sec = f->atime.tv_sec;
        stxbuf.stx_atime.tv_nsec = f->atime.tv_nsec;
        stxbuf.stx_btime.tv_sec = f->btime.tv_sec;
        stxbuf.stx_btime.tv_nsec = f->btime.tv_nsec;
        stxbuf.stx_ctime.tv_sec = f->ctime.tv_sec;
        stxbuf.stx_ctime.tv_nsec = f->ctime.tv_nsec;
        stxbuf.stx_mtime.tv_sec = f->mtime.tv_sec;
        stxbuf.stx_mtime.tv_nsec = f->mtime.tv_nsec;
        stxbuf.stx_dev_major = major(config.dev);
        stxbuf.stx_dev_minor = minor(config.dev);
        fuse_reply_statx(req, flags, &stxbuf, 1.0);
    } else {
        fuse_reply_err(req, ENOENT);
    }
}

void smt_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi)
{
    (void)fi;
    struct dirbuf b;

    memset(&b, 0, sizeof(b));

    dirbuf_add(req, &b, ".", ino);
    dirbuf_add(req, &b, "..", ino);

    khint_t k = add_opendir(ino);
    if (k != kh_end(opendirh)) {
        struct opendirinfo *opendir = kh_val(opendirh, k);
        lvisit.visits[opendir->index].visit = lvisit.currvisit++;
        kbitr_t itr;
        kb_itr_first(kbt_fnames, opendir->fnames, &itr);
        for (; kb_itr_valid(&itr); kb_itr_next(kbt_fnames, opendir->fnames, &itr)) {
            struct opendirentry *fin = &kb_itr_key(struct opendirentry, &itr);
            dirbuf_add(req, &b, fin->name, fin->ino);
        }
    }

    reply_buf_limited(req, b.p, b.size, off, b.size);
    free(b.p);
}

static void smt_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode) {

    struct fuse_entry_param e;
    memset(&e, 0, sizeof(e));

    if (freemap->ino < MAX_FILES) {
        khint_t k = kh_get(dirhash, dirh, name); //make sure the name isn't already present
        if (k == kh_end(dirh)) {
            ino_t ino;

            char const *pos = strchr(name, '\\');
            if (pos != NULL && (pos-name)+1 != strlen(name)) {
                ino = dirset(name, pos);
            } else {
                ino = add_file(config.blksize, name, S_IFDIR | mode);
            }

            if (ino) {
                k = kh_get(openfilehash, fcache, parent);
                if (k != kh_end(fcache)) {
                    struct openfileinfo *fp = kh_value(fcache, k);
                    if (parent != TAGS) {
                        add_filetodir(fp->name, ino);
                    }

                    k = kh_get(openfilehash, fcache, ino);
                    if (k != kh_end(fcache)) {
                        struct openfileinfo *f = kh_value(fcache, k);

                        e.ino = ino;
                        e.attr.st_ino = ino;
                        e.attr.st_mode = f->mode;
                        e.attr.st_nlink = f->nlink;
                        e.attr.st_size = f->size;

                        if (!f->fd) {
                            fuse_reply_entry(req, &e);
                        } else {
                            fuse_reply_err(req, f->fd);
                        }
                    } else {
                        fuse_reply_err(req, ENOENT);
                    }
                } else {
                    fuse_reply_err(req, ENOENT);
                }
            } else {
                fuse_reply_err(req, ENOENT);
            }
        } else {
            fuse_reply_err(req, EEXIST);
        }
        return;
    }

    fuse_reply_err(req, ENOSPC);
}

static void smt_rename(fuse_req_t req, fuse_ino_t parent, const char *name, fuse_ino_t newparent, const char *newname, unsigned int flags)
{
	int res = ENOENT;

	if (parent == ROOT) { //can't rename directories in root
		fuse_reply_err(req, EPERM);
		return;
	}

    khint_t k;
    k = add_opendir(parent);

    if (k != kh_end(opendirh)) {
        struct opendirinfo *opendir = kh_val(opendirh, k);

        struct opendirentry *fin = calloc(1, sizeof(struct opendirentry));
        fin->name = (char*)malloc(strlen(name)+1);
        strncpy(fin->name, name, strlen(name));
        fin->name[strlen(name)] = '\0';

        struct opendirentry *entry = kb_getp(kbt_fnames, opendir->fnames, fin);
        if (entry) {
            k = kh_get(openfilehash, fcache, entry->ino);
            if (k != kh_end(fcache)) {
                struct openfileinfo *f = kh_value(fcache, k);
                struct dirinfo *olddir = NULL;

                if (strncmp(name, newname, max(strlen(name), strlen(newname)))) {
                    if ((f->mode & S_IFMT) == S_IFDIR) {
                        k = kh_get(dirhash, dirh, newname);
                        if (k != kh_end(dirh)) {
                            fuse_reply_err(req, EEXIST);
                            return;
                        }

                        k = kh_get(dirhash, dirh, name);
                        if (k != kh_end(dirh)) {
                            olddir = kh_value(dirh, k);
                        }
                    }

                    free(f->name);
                    f->name = (char*) malloc(strlen(newname)+1);
                    strncpy(f->name, newname, strlen(newname));
                    f->name[strlen(newname)] = '\0';

                    if ((f->mode & S_IFMT) == S_IFDIR) {
                        add_directory(olddir->ino, f->name);

                        kbitr_t itr;
                        kb_itr_first(kbt_fileinos, opendir->fileinos, &itr);
                        for (; kb_itr_valid(&itr); kb_itr_next(kbt_fileinos, opendir->fileinos, &itr)) {
                            ino_t fino = kb_itr_key(ino_t, &itr);
                            set_file_xattr(fino, f->name, ADD);
                            set_file_xattr(fino, name, RMV);
                        }

                        k = kh_get(dirhash, dirh, name);
                        kh_del(dirhash, dirh, k);
                        free(olddir->name);
                        free(olddir);
                    }

                    for (int i = 0; i < f->dirinosize; i++) {
                        k = kh_get(opendirhash, opendirh, f->dirinos[i]);
                        if (k != kh_end(opendirh)) {
                            refreshdir(NULL, NULL, f->dirinos[i], 0);
                        }
                    }

                    clock_gettime(CLOCK_REALTIME, &f->ctime);

                    if (config.passthrough && (f->mode & S_IFMT) != S_IFDIR) {
                        rename_symlink(f->ino, f->name);
                    }
                }

                if (parent != newparent) {
                    k = kh_get(openfilehash, fcache, newparent);
                    if (k != kh_end(fcache)) {
                        struct openfileinfo *fp = kh_value(fcache, k);
                        add_filetodir(fp->name, f->ino);
                    } else {
                        append_dir_contents(newparent, f->ino);
                    }
                }

                res = 0;
            }
        }
        free(fin->name);
        free(fin);
    }

	fuse_reply_err(req, res);
}

static void smt_create(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode, struct fuse_file_info *fi) {
    struct fuse_entry_param e;
    memset(&e, 0, sizeof(e));

    khint_t k = kh_get(openfilehash, fcache, parent);
    if (k != kh_end(fcache)) {
        struct openfileinfo *fp = kh_value(fcache, k);
        if (freemap->ino < MAX_FILES && fp->dirinosize < MAX_DIRSIZE) {
            if (parent > TAGS && ((mode & S_IFMT) != S_IFDIR) && ((fp->mode & S_IFMT) == S_IFDIR)) {
                ino_t ino = add_file(0x0, name, S_IFREG | mode);

                if (parent != FILES) {
                    add_filetodir(fp->name, ino);
                }

                k = kh_get(openfilehash, fcache, ino);
                if (k != kh_end(fcache)) {
                    struct openfileinfo *f = kh_value(fcache, k);

                    e.ino = ino;
                    e.attr.st_ino = ino;
                    e.attr.st_mode = f->mode;
                    e.attr.st_nlink = f->nlink;
                    e.attr.st_size = f->size;

                    if (f->fd) {
                        fi->fh = f->fd;
                        fuse_reply_create(req, &e, fi);
                    } else {
                        fuse_reply_err(req, EBADF);
                    }
				} else {
					fuse_reply_err(req, ENOENT);
				}
			} else {
					fuse_reply_err(req, EPERM);
			}
        } else {
            fuse_reply_err(req, ENOSPC);
        }
        return;
    }

    fuse_reply_err(req, ENOENT);
}

static void smt_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {

    khint_t k = kh_get(openfilehash, fcache, ino);
    if (k != kh_end(fcache)) {
        struct openfileinfo *f = kh_val(fcache, k);
        if ((f->mode & S_IFMT) != S_IFDIR) {
            char *filepath = get_ino_path(config.storage, ino);
            if (filepath) {
                int fd;
                int32_t flag = 0;
                if (!config.passthrough) { //ensure file descriptor to imported file is read-only if passthrough isn't set
                    struct stat stbuf;
                    memset(&stbuf, 0, sizeof(stbuf));
                    stat(filepath, &stbuf);
                    if ((stbuf.st_mode & S_IFMT) == S_IFLNK) {
                        flag |= O_RDONLY;
                    }
                }

                fd = open(filepath, fi->flags | flag);
                if (fd) {
                    fi->fh = fd;
                    fuse_reply_open(req, fi);
                } else {
                    fuse_reply_err(req, EBADF);
                }
                free(filepath);
            } else {
                fuse_reply_err(req, ENOMEM);
            }
        } else {
            fuse_reply_err(req, EISDIR);
        }
    } else {
        fuse_reply_err(req, ENOENT);
    }
}

static void smt_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi) {
    (void) fi;

    khint_t k = kh_get(openfilehash, fcache, ino);
    if (k == kh_end(fcache)) {
        k = add_openfile(ino);
    }
    if (k != kh_end(fcache)) {
        struct openfileinfo *f = kh_value(fcache, k);
        if ((f->mode & S_IFMT) == S_IFDIR) {
            fuse_reply_err(req, EISDIR);
        } else {
            struct fuse_bufvec buf = FUSE_BUFVEC_INIT(size);
            buf.buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
            buf.buf[0].fd = fi->fh;
            buf.buf[0].pos = off;
            fuse_reply_data(req, &buf, FUSE_BUF_SPLICE_MOVE);
            free(buf.buf->mem);
            /*if (off < f->size) {
                void *buf = malloc(size);
                if (buf) {
                    read(fi->fh, buf, size);
                    reply_buf_limited(req, buf, size, off, f->size);
                    free(buf);
                } else {
                    fuse_reply_err(req, ENOMEM);
                }
            } else {
                fuse_reply_buf(req, NULL, 0);
            }*/
        }
        return;
    }
    fuse_reply_err(req, ENOENT);
}

static void smt_unlink(fuse_req_t req, fuse_ino_t parent, const char *name) {
	int res = ENOENT;
    khint_t k;

    k = add_opendir(parent);

    if (k != kh_end(opendirh)) {
        struct opendirinfo *opendir = kh_val(opendirh, k);

        struct opendirentry *fin = calloc(1, sizeof(struct opendirentry));
        fin->name = (char*)malloc(strlen(name)+1);
        strncpy(fin->name, name, strlen(name));
        fin->name[strlen(name)] = '\0';

        struct opendirentry *entry = kb_getp(kbt_fnames, opendir->fnames, fin);
        if (entry) {
            khint_t k = kh_get(openfilehash, fcache, entry->ino);
            if (k != kh_end(fcache)) {
                struct openfileinfo *f = kh_value(fcache, k);
                khint_t k = kh_get(openfilehash, fcache, parent);
                if (k != kh_end(fcache)) {
                    struct openfileinfo *fp = kh_value(fcache, k);
                    remove_filefromdir(fp->name, f->ino);
                }

                if (parent == FILES) { //if unlinking from _FILES, unlink from everywhere and free file
                    remove_file(f->ino);
                } else {
                    clock_gettime(CLOCK_REALTIME, &f->ctime);
                }
                res = 0;
            }
        }
        free(fin->name);
        free(fin);
    }

	fuse_reply_err(req, res);
}

static void smt_rmdir(fuse_req_t req, fuse_ino_t parent, const char *name) {
    int res = ENOENT;
    khint_t k;

    k = kh_get(dirhash, dirh, name);
    if (k != kh_end(dirh)) { //check if dir
        struct dirinfo *dir = kh_value(dirh, k);

        khint_t k = kh_get(openfilehash, fcache, dir->ino);
        if (k != kh_end(fcache)) {
            struct openfileinfo *f = kh_value(fcache, k);
            if (dir->ino > SYSDIR) {
                khint_t k = kh_get(openfilehash, fcache, parent);
                if (k != kh_end(fcache)) {
                    struct openfileinfo *fp = kh_value(fcache, k);
                    remove_filefromdir(fp->name, dir->ino);
                }

                if (parent == TAGS) { //if unlinking from /, unlink from everywhere and free file
                    remove_file(dir->ino);
                } else {
                    clock_gettime(CLOCK_REALTIME, &f->ctime);
                }
                res = 0;
            } else {
				res = EPERM;
			}
        }
    }
    fuse_reply_err(req, res);
}

static void smt_write(fuse_req_t req, fuse_ino_t ino, const char *buf, size_t size, off_t off, struct fuse_file_info *fi) {

    struct stat stbuf;
    memset(&stbuf, 0, sizeof(stbuf));

    khint_t k = add_openfile(ino);
    if (k != kh_end(fcache)) {
        struct openfileinfo *f = kh_value(fcache, k);
        if ((f->mode & S_IFMT) == S_IFDIR) {
            fuse_reply_err(req, EISDIR);
        } else {
            off_t res = write(fi->fh, buf, size);
            if (res != -1) {
                fstat(fi->fh, &stbuf);
                f->size = stbuf.st_size;
                f->blocks = stbuf.st_blocks;
                clock_gettime(CLOCK_REALTIME, &f->ctime);
                clock_gettime(CLOCK_REALTIME, &f->mtime);
                fuse_reply_write(req, res);
            } else {
                fuse_reply_err(req, errno);
            }
        }
    } else {
		fuse_reply_err(req, ENOENT);
	}
}

static void smt_flush(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
	int res;
	res = close(dup(fi->fh));
	fuse_reply_err(req, res == -1 ? errno : 0);
}
//! custom release?

static void smt_statfs(fuse_req_t req, fuse_ino_t ino)
{
	int res;
	struct statvfs stbuf;

	res = fstatvfs(config.root_fd, &stbuf);
	if (res == -1)
		fuse_reply_err(req, errno);
	else
		fuse_reply_statfs(req, &stbuf);
}

static void smt_listxattr(fuse_req_t req, fuse_ino_t ino, size_t size)
{
	char *value = NULL;
    ssize_t ret = 0;
    struct openfileinfo *f = NULL;

    khint_t k = kh_get(openfilehash, fcache, ino);
    if (k == kh_end(fcache)) {
        k = add_openfile(ino);
    }
    if (k != kh_end(fcache)) {
        f = kh_value(fcache, k);
    }

    if (size) {
        value = (char *)malloc(size);
        if (!value) {
            fuse_reply_err(req, ENOMEM);
            return;
        }
        char *p = value;

        for (int i = 0; i < f->dirinosize; i++) {
            k = kh_get(openfilehash, fcache, f->dirinos[i]);
            if (k != kh_end(fcache)) {
                struct openfileinfo *fd = kh_value(fcache, k);
                p = memccpy(p, fd->name, '\0', strlen(fd->name)+1);
            } else {
                char *dirname = get_xattr_from_file(f->dirinos[i], "user.smtfs_m.name");
                p = memccpy(p, dirname, '\0', strlen(dirname)+1);
                free(dirname);
            }
        }

		fuse_reply_buf(req, value, size);
    } else {
        for (int i = 0; i < f->dirinosize; i++) {
            k = kh_get(openfilehash, fcache, f->dirinos[i]);
            if (k != kh_end(fcache)) {
                struct openfileinfo *fd = kh_value(fcache, k);
                ret += strlen(fd->name)+1;
            } else {
                char *dirname = get_xattr_from_file(f->dirinos[i], "user.smtfs_m.name");
                ret += strlen(dirname)+1;
                free(dirname);
            }
        }

		fuse_reply_xattr(req, ret);
    }
    free(value);
}

static void smt_getxattr(fuse_req_t req, fuse_ino_t ino, const char *name, size_t size) {

    if (!strncmp(name, "security.capability", strlen(name))) {
        fuse_reply_err(req, EOPNOTSUPP);
        return;
    }

    if (size) {
        khint_t k;
        k = kh_get(dirhash, dirh, name);
        if (k != kh_end(dirh)) { //check if dir exists
            fuse_reply_buf(req, name, size);
        } else {
            fuse_reply_err(req, ENOENT);
        }
    } else {
        fuse_reply_xattr(req, strlen(name)+1); //size of value is 0
    }
}

int recursive_dir(ino_t dirino, ino_t ino) {
    if (dirino == ino) {
        return EPERM;
    }

    int saverr = 0;

    //kbitr_t itr;
    khint_t k = kh_get(openfilehash, fcache, dirino);
    if (k == kh_end(fcache)) {
        k = add_openfile(dirino);
    }
    if (k != kh_end(fcache)) {
        struct openfileinfo *f = kh_value(fcache, k);
        for (int i = 0; i < f->dirinosize; i++) {
            ino_t inod = f->dirinos[i];
            saverr = recursive_dir(inod, ino);
            if (saverr) {
                return saverr;
            }
        }
    }

    return saverr;
}

static void smt_setxattr(fuse_req_t req, fuse_ino_t ino, const char *name, const char *value, size_t size, int flags) {
    int saverr = EPERM;

    if (ino <= SYSDIR) { //don't allow tagging system directories
        fuse_reply_err(req, saverr);
        return;
    }
    if (!strncmp(name, "user.smtfs", strlen("user.smtfs"))) { //!figure out what causes these calls
        fuse_reply_err(req, EOPNOTSUPP);
        return;
    }

    khint_t k;
    k = kh_get(dirhash, dirh, name);

    if (k != kh_end(dirh)) {
        struct dirinfo *dir = kh_value(dirh, k);
        if (dir->ino == ROOT) {
            fuse_reply_err(req, saverr);
            return;
        }

        k = kh_get(openfilehash, fcache, ino);
        if (k == kh_end(fcache)) {
            k = add_openfile(ino);
        }
        if (k != kh_end(fcache)) {
            struct openfileinfo *f = kh_value(fcache, k);
            if ((f->mode & S_IFMT) != S_IFDIR && dir->ino == TAGS) {
                fuse_reply_err(req, saverr);
                return;
            }

            int pos = find_dirino_pos(f, dir->ino);
            if (f->dirinos[pos] == dir->ino) { //check if dir being added is already present
                fuse_reply_err(req, EEXIST);
                return;
            }

            if ((f->mode & S_IFMT) == S_IFDIR) {
                saverr = recursive_dir(dir->ino, ino); //check for A->..->A circular relation
                if (saverr) {
                    fuse_reply_err(req, saverr);
                    return;
                }
            }
            saverr = add_filetodir(name, ino);
        }
    } else {
        saverr = add_file(config.blksize, name, S_IFDIR | 0777);
        saverr = add_filetodir(name, ino);
    }

    fuse_reply_err(req, saverr);
}

static void smt_removexattr(fuse_req_t req, fuse_ino_t ino, const char *name) {
    int saverr = ENOENT;
    khint_t k;

    if (ino < SYSDIR) { //don't allow removal from system directories
        fuse_reply_err(req, EPERM);
        return;
    }

    k = kh_get(dirhash, dirh, name);
    if (k != kh_end(dirh)) {
        struct dirinfo *dir = kh_value(dirh, k);
		if (dir->ino < SYSDIR) { //don't allow removal from _TAGS or _FILES via xattr
			fuse_reply_err(req, EPERM);
			return;
		}

        k = kh_get(openfilehash, fcache, ino);
        if (k == kh_end(fcache)) {
            k = add_openfile(ino);
        }
        if (k != kh_end(fcache)) {
            struct openfileinfo *f = kh_value(fcache, k);

            int pos = find_dirino_pos(f, dir->ino);
            if (f->dirinos[pos] == dir->ino) { //check if present
                remove_filefromdir(name, ino);
                saverr = 0;
            }
        }
    }
    fuse_reply_err(req, saverr);
}

int is_importdir_invalid(char* importdir) {
    DIR *imfd = opendir(importdir);
    if (imfd) {
        closedir(imfd);
        return 0;
    } else {
        printf("Incorrect import argument\n");
        return 1;
    }
}

static struct fuse_lowlevel_ops operations = {
    .init = smt_init,
    .destroy = smt_destroy,
    .access = smt_access,
    .lookup = smt_lookup,
    .forget = smt_forget,
    .getattr = smt_getattr,
    .setattr = smt_setattr,
    .statx = smt_statx,
    .readdir = smt_readdir,
    .open = smt_open,
    .read = smt_read,
    .mkdir = smt_mkdir,
    .rename = smt_rename,
    .create = smt_create,
    .unlink = smt_unlink,
    .rmdir = smt_rmdir,
    .write = smt_write,
    .flush = smt_flush,
    .statfs = smt_statfs,
    .listxattr = smt_listxattr,
    .getxattr = smt_getxattr,
    .setxattr = smt_setxattr,
    .removexattr = smt_removexattr,
};

enum {
     KEY_HELP,
     KEY_VERSION,
};

#define SMTFS_OPT(t, p, v) { t, offsetof(struct fuse_smt_userdata, p), v }

static struct fuse_opt smtfs_opts[] = {
     SMTFS_OPT("import=%s",         import, 0),
     SMTFS_OPT("-p",                passthrough, 1),
     SMTFS_OPT("--passthrough",     passthrough, 1),
     SMTFS_OPT("-r",                refresh, 1),
     SMTFS_OPT("--refresh",         refresh, 1),
     FUSE_OPT_KEY("-V",             KEY_VERSION),
     FUSE_OPT_KEY("--version",      KEY_VERSION),
     FUSE_OPT_KEY("-h",             KEY_HELP),
     FUSE_OPT_KEY("--help",         KEY_HELP),
     FUSE_OPT_END
};

static int smtfs_opt_proc(void *data, const char *arg, int key, struct fuse_args *outargs) {
    return 1;
}

int main(int argc, char **argv)
{
    int retval = 0;
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct fuse_cmdline_opts opts;
    struct fuse_smt_userdata conf;
    struct fuse_session *se;

    memset(&conf, 0, sizeof(conf));

    fuse_opt_parse(&args, &conf, smtfs_opts, smtfs_opt_proc);

    if (fuse_parse_cmdline(&args, &opts)) {
        return 1;
    }
    if (opts.show_help) {
        printf("Usage: %s <mountpoint> [options]\n", argv[0]);
        printf("smtfs options:\n"
               "    -r   --refresh         refresh imports\n"
               "    -p   --passthrough     pass operations to the import directory\n"
               "fuse options:\n");
        fuse_cmdline_help();
        fuse_lowlevel_help();
        return 0;
    }
    if (opts.show_version) {
        printf("FUSE library version %s\n", fuse_pkgversion());
        fuse_lowlevel_version();
        return 0;
    }
    if (opts.mountpoint == NULL) {
        printf("Usage: %s <mountpoint> [options]\n", argv[0]);
        return 1;
    }

    devfile = realpath(opts.mountpoint, NULL);
    DIR *rootdir = opendir(devfile);
    conf.root_fd = dirfd(rootdir);
    struct stat stbuf;
    memset(&stbuf, 0, sizeof(stbuf));
    fstat(conf.root_fd, &stbuf);
    conf.dev = stbuf.st_dev;
    conf.blksize = stbuf.st_blksize;

    char *storage = malloc(PATH_MAX);
    char *backup = malloc(PATH_MAX);
    char *dirpath = strdup(dirname(devfile));
    if (storage && backup) {
        storage[0] = '\0';
        strcat(storage, dirpath);
        strcat(storage, "/.smtfs_storage");
        mkdir(storage, 0700);
        conf.storage = storage;

        backup[0] = '\0';
        strcat(backup, dirpath);
        strcat(backup, "/.smtfs_backup");
        mkdir(backup, 0700);
        conf.backup = backup;
    } else {
        free(opts.mountpoint);
        fuse_opt_free_args(&args);
        return 1;
    }

    if (conf.import) { //check all import sources
        char *importdir = conf.import;
        if (strchr(conf.import, '&')) {
            char *q = importdir;
            while ((q = strchr(q, '&'))) {
                *q = '\0';
                if (is_importdir_invalid(importdir)) {
                    free(opts.mountpoint);
                    fuse_opt_free_args(&args);
                    return 1;
                }
                *q = '&';
                importdir = ++q;
            }
        }
        if (is_importdir_invalid(importdir)) {
            free(opts.mountpoint);
            fuse_opt_free_args(&args);
            return 1;
        }
    }

    se = fuse_session_new(&args, &operations, sizeof(operations), &conf);
    if (se == NULL) {
        free(opts.mountpoint);
        fuse_opt_free_args(&args);
        return 1;
    }

    if (fuse_set_signal_handlers(se) != 0) {
        retval = 1;
        goto errlabel_two;
    }

    if (fuse_session_mount(se, opts.mountpoint) != 0) {
        retval = 1;
        goto errlabel_one;
    }

    fuse_session_loop(se);

    fuse_session_unmount(se);
errlabel_one:
    fuse_remove_signal_handlers(se);

errlabel_two:
    fuse_session_destroy(se);
    free(opts.mountpoint);
    free(devfile);
    closedir(rootdir);
    free(conf.import);
    free(conf.storage);
    free(conf.backup);
    free(dirpath);
    close(conf.root_fd);
    fuse_opt_free_args(&args);
    return retval;
}


