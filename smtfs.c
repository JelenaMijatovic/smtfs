#define FUSE_USE_VERSION FUSE_MAKE_VERSION(3, 17)

#define MAX_FILES 10000
#define MAX_FCSIZE 100
#define MAX_DCSIZE 100
#define MAX_OPEN 20
#define MAX_FILENAME_LEN 256

#define ROOT 1
#define TAGS 2
#define FILES 3
#define HOME 4
#define SYSDIR 4

#define min(x, y) ((x) < (y) ? (x) : (y))

#include <fuse3/fuse_lowlevel.h>
#include "khash.h"
#include "ksort.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <time.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <limits.h>

#define BITMASK(b) (1 << ((b) % CHAR_BIT))
#define BITSLOT(b) ((b) / CHAR_BIT)
#define BITSET(a, b) ((a)[BITSLOT(b)] |= BITMASK(b))
#define BITTEST(a, b) ((a)[BITSLOT(b)] & BITMASK(b))
#define BITNSLOTS(nb) ((nb + CHAR_BIT - 1) / CHAR_BIT)

char *devfile = NULL;
char *storage = NULL;

struct fileino {
    ino_t ino;
    struct fileino *next;
};

struct file_info
{
    ino_t ino;
    int fd;
    char *name;
    size_t size;
    char *data;
    mode_t mode;
    nlink_t nlink;
    short int dirty;
    struct timespec atime;
    struct timespec mtime;
    struct timespec ctime;
    struct fileino *dir; //MAX_DCSIZE cut of directories
};

struct file_info *filemap;

struct freemap {
    int currfree;
    ino_t *nextfr;
};

struct freemap frmp;

struct dirinfo {
    ino_t ino;
    struct fileino *files; //MAX_FCSIZE cut of files
};

KHASH_MAP_INIT_STR(dirhash, struct dirinfo*)
khash_t(dirhash) *dirh;

struct opendirinfo {
    ino_t index;
    ino_t *fileinos;
    char **filenames;
};

KHASH_MAP_INIT_INT(opendirhash, struct opendirinfo*)
khash_t(opendirhash) *opendirh;

KHASH_MAP_INIT_STR(filenamehash, int)

struct vst {
    int visit;
    int ino;
};

struct last_visited {
    int currindex;
    int currvisit;
    struct vst *visits; //MAX_OPEN
};

#define vst_lt(a, b) ((a).visit < (b).visit)
KSORT_INIT(vst, struct vst, vst_lt);
struct last_visited lvisit;

struct dirbuf {
	char *p;
	size_t size;
};

void refreshdir(fuse_req_t req, struct dirbuf *b, ino_t ino, int addbuff);

struct dirinfo* add_directory(ino_t ino, const char* name) {

    struct dirinfo *dir = NULL;
    khint_t k;
    int absent;

    k = kh_get(dirhash, dirh, name);
    if (k == kh_end(dirh)) {
        dir = malloc(sizeof(struct dirinfo));
        if (dir) {
            dir->ino = ino;
            dir->files = calloc(MAX_FCSIZE, sizeof(struct fileino));
            if (!dir->files) {
                free(dir);
                return NULL;
            }
            k = kh_put(dirhash, dirh, filemap[ino].name, &absent);
            kh_val(dirh, k) = dir;
        }
    } else {
        dir = kh_val(dirh, k);
    }

    return dir;
}

ino_t add_ino(struct fileino *fileinos, ino_t ino, int mod) {
    if (!fileinos[(ino-1)%mod].ino) {
        fileinos[(ino-1)%mod].ino = ino;
        fileinos[(ino-1)%mod].next = NULL;
        return ino;
    } else {
        struct fileino *node = &fileinos[(ino-1)%mod];
        while (node->next != NULL) {
            node = node->next;
        }
        node->next = malloc(sizeof(struct fileino));
        if (node->next) {
            node->next->ino = ino;
            node->next->next = NULL;
            return ino;
        }
    }
    return 0;
}

void remove_ino(struct fileino *fileinos, ino_t ino, int mod) {
    if (fileinos[(ino-1)%mod].ino == ino) {
        if (fileinos[(ino-1)%mod].next) {
            struct fileino *node = fileinos[(ino-1)%mod].next;
            fileinos[(ino-1)%mod] = *(fileinos[(ino-1)%mod].next);
            free(node);
        } else {
            fileinos[(ino-1)%mod].ino = 0;
        }
    } else {
        struct fileino *prev = &fileinos[(ino-1)%mod];
        struct fileino *node = prev->next;
        while (node) {
            if (node->ino == ino) {
                prev->next = node->next;
                free(node);
                break;
            }
            prev = node;
            node = node->next;
        }
    }
}

int add_filetodir(const char *name, ino_t ino) {

    struct dirinfo *dir;
    khint_t k;

    k = kh_get(dirhash, dirh, name);
    if (k != kh_end(dirh)) {
        dir = kh_val(dirh, k);

        //link directory and file both ways
        if (!add_ino(dir->files, ino, MAX_FCSIZE)) {
            return EPERM;
        }
        if (!add_ino(filemap[ino].dir, dir->ino, MAX_DCSIZE)) {
            remove_ino(dir->files, ino, MAX_FCSIZE);
            return EPERM;
        }

        filemap[ino].nlink++;
        clock_gettime(CLOCK_REALTIME, &filemap[ino].ctime);
        clock_gettime(CLOCK_REALTIME, &filemap[dir->ino].ctime);
        clock_gettime(CLOCK_REALTIME, &filemap[dir->ino].mtime);

        k = kh_get(opendirhash, opendirh, dir->ino);
        if (k != kh_end(opendirh))
            refreshdir(NULL, NULL, dir->ino, 0);

        printf("adding ino %ld to %ld\n", ino, dir->ino);
        return 0;
    }

    return EPERM;
}

void remove_filefromdir(const char *name, ino_t ino) {
    struct dirinfo *dir;
    khint_t k;

    k = kh_get(dirhash, dirh, name);
    if (k != kh_end(dirh)) {
        dir = kh_val(dirh, k);

        remove_ino(dir->files, ino, MAX_FCSIZE);
        remove_ino(filemap[ino].dir, dir->ino, MAX_DCSIZE);

        filemap[ino].nlink--;
        clock_gettime(CLOCK_REALTIME, &filemap[ino].ctime);
        clock_gettime(CLOCK_REALTIME, &filemap[dir->ino].ctime);
        clock_gettime(CLOCK_REALTIME, &filemap[dir->ino].mtime);

        k = kh_get(opendirhash, opendirh, dir->ino);
        if (k != kh_end(opendirh))
            refreshdir(NULL, NULL, dir->ino, 0);
    }
    printf("nlink after remove_filefromdir: %ld\n", filemap[ino].nlink);
}

void remove_directory(const char *name) {
    struct dirinfo *dir = NULL;
    khint_t k;

    k = kh_get(dirhash, dirh, name);
    if (k != kh_end(dirh)) {
        dir = kh_val(dirh, k);
        for (int i = 0; i < MAX_FCSIZE; i++) {
            if (dir->files[i].ino) {
                remove_filefromdir(name, dir->files[i].ino);
                struct fileino *node = dir->files[i].next;
                while (node) {
                    struct fileino *prev = node;
                    remove_filefromdir(name, node->ino);
                    node = node->next;
                    free(prev);
                }
            }
        }
        free(dir->files);
        free(dir);
        kh_del(dirhash, dirh, k);
    }
}

static int add_sysdirs(const char *name, mode_t mode) {
    if (frmp.currfree < MAX_FILES) {
        filemap[frmp.currfree].ino = frmp.currfree;
        filemap[frmp.currfree].name = (char *)malloc(MAX_FILENAME_LEN);
        if (filemap[frmp.currfree].name) {
            strncpy(filemap[frmp.currfree].name, name, strlen(name)+1);
            filemap[frmp.currfree].name[strlen(name)] = 0x0;
        }
        filemap[frmp.currfree].size = 0x0;
        filemap[frmp.currfree].data = 0x0;
        filemap[frmp.currfree].mode = mode;
        filemap[frmp.currfree].dir = calloc(MAX_DCSIZE, sizeof(struct fileino));

        if (!(filemap[frmp.currfree].name && filemap[frmp.currfree].dir)) {
            filemap[frmp.currfree].ino = 0;
            free(filemap[frmp.currfree].name);
            free(filemap[frmp.currfree].data);
            free(filemap[frmp.currfree].dir);
            return 0;
        }
        filemap[frmp.currfree].nlink = 1;
        struct dirinfo *ret = add_directory(frmp.currfree, name);
        if (!ret) {
            if (ret) {
                remove_directory(name);
            }
            filemap[frmp.currfree].ino = 0;
            free(filemap[frmp.currfree].name);
            free(filemap[frmp.currfree].data);
            free(filemap[frmp.currfree].dir);
            return 0;
        }
        clock_gettime(CLOCK_REALTIME, &filemap[frmp.currfree].atime);
        clock_gettime(CLOCK_REALTIME, &filemap[frmp.currfree].mtime);
        clock_gettime(CLOCK_REALTIME, &filemap[frmp.currfree].ctime);

        ino_t ino = frmp.currfree;
        frmp.currfree = frmp.nextfr[frmp.currfree];
        return ino;
    }
    return 0;
}

int add_file(size_t size, char *data, const char *name, mode_t mode) {

    if (frmp.currfree < MAX_FILES) {
        filemap[frmp.currfree].ino = frmp.currfree;
        filemap[frmp.currfree].name = (char *)malloc(MAX_FILENAME_LEN);
        if (filemap[frmp.currfree].name) {
            strncpy(filemap[frmp.currfree].name, name, strlen(name)+1);
            filemap[frmp.currfree].name[strlen(name)] = 0x0;
        }
        filemap[frmp.currfree].size = size;
        filemap[frmp.currfree].data = data;
        filemap[frmp.currfree].mode = mode;
        filemap[frmp.currfree].dirty = 0;
        filemap[frmp.currfree].dir = calloc(MAX_DCSIZE, sizeof(struct fileino));

        if (!(filemap[frmp.currfree].name && filemap[frmp.currfree].dir)) {
            filemap[frmp.currfree].ino = 0;
            free(filemap[frmp.currfree].name);
            free(filemap[frmp.currfree].data);
            free(filemap[frmp.currfree].dir);
            return 0;
        }

        if ((mode & S_IFMT) == S_IFDIR) {
            filemap[frmp.currfree].nlink = 1;
            struct dirinfo *ret = add_directory(frmp.currfree, name);
            if (!ret || add_filetodir(filemap[TAGS].name, frmp.currfree)) { //_TAGS contains all directories except those in root
                if (ret) {
                    remove_directory(name);
                }
                filemap[frmp.currfree].ino = 0;
                free(filemap[frmp.currfree].name);
                free(filemap[frmp.currfree].data);
                free(filemap[frmp.currfree].dir);
                return 0;
            }
        } else {
            filemap[frmp.currfree].nlink = 0;
            if (add_filetodir(filemap[FILES].name, frmp.currfree)) { //_FILES contains all regular files
                filemap[frmp.currfree].ino = 0;
                free(filemap[frmp.currfree].name);
                free(filemap[frmp.currfree].data);
                free(filemap[frmp.currfree].dir);
                return 0;
            }
        }
        clock_gettime(CLOCK_REALTIME, &filemap[frmp.currfree].atime);
        clock_gettime(CLOCK_REALTIME, &filemap[frmp.currfree].mtime);
        clock_gettime(CLOCK_REALTIME, &filemap[frmp.currfree].ctime);

        ino_t ino = frmp.currfree;
        frmp.currfree = frmp.nextfr[frmp.currfree];
        return ino;
    }
    return 0;
}

int remove_file(ino_t ino) {

    for (int i = 0; i < MAX_DCSIZE; i++) {
        while (filemap[ino].dir[i].ino) {
            remove_filefromdir(filemap[filemap[ino].dir[i].ino].name, ino);
            if (filemap[ino].dir[i].next) {
                struct fileino *temp = filemap[ino].dir[i].next;
                filemap[ino].dir[i] = *(filemap[ino].dir[i].next);
                free(temp);
            } else {
                filemap[ino].dir[i].ino = 0;
            }
        }
    }

    if ((filemap[ino].mode & S_IFMT) == S_IFDIR) {
        remove_directory(filemap[ino].name);
        filemap[ino].nlink--;
    }

    free(filemap[ino].name);
    free(filemap[ino].data);
    free(filemap[ino].dir);
    filemap[ino].ino = 0;

    if (ino < frmp.currfree) {
        frmp.nextfr[ino] = frmp.currfree;
        frmp.currfree = ino;
    } else {
        ino_t curr = frmp.nextfr[frmp.currfree];
        ino_t prev = frmp.currfree;
        while (curr < ino) {
            prev = curr;
            curr = frmp.nextfr[curr];
        }
        frmp.nextfr[ino] = curr;
        frmp.nextfr[prev] = ino;
    }
    printf("removed file %ld\n", ino);
    return ino;
}

void remove_opendir(ino_t ino) {
    khint_t k;

    k = kh_get(opendirhash, opendirh, ino);
    if (k != kh_end(opendirh)) {
        struct opendirinfo *opendir = kh_val(opendirh, k);
        lvisit.currindex = opendir->index;
        free(opendir->fileinos);
        for (int i = 0; i < MAX_FILES; i++) {
            free(opendir->filenames[i]);
        }
        free(opendir->filenames);
        free(opendir);
        kh_del(opendirhash, opendirh, ino);
    }
}

khint_t add_opendir(ino_t ino) {

    khint_t k;
    int absent;
    if (filemap[ino].ino && ((filemap[ino].mode & S_IFMT) == S_IFDIR)) {
        k = kh_get(opendirhash, opendirh, ino);
        if (k == kh_end(opendirh)) {
            if (kh_size(opendirh) >= MAX_OPEN) {
                struct vst *visits = lvisit.visits;
                struct vst t = ks_ksmall(vst, MAX_OPEN, visits, 0);
                remove_opendir(t.ino);
            }
            struct opendirinfo *dir = malloc(sizeof(struct opendirinfo));
            if (dir) {
                dir->index = lvisit.currindex++;
                lvisit.visits[dir->index].visit = lvisit.currvisit++;
                lvisit.visits[dir->index].ino = ino;
                dir->fileinos = calloc(MAX_FILES, sizeof(ino_t));
                dir->filenames = calloc(MAX_FILES, sizeof(int *));

                if (dir->fileinos && dir->filenames) {
                    k = kh_put(opendirhash, opendirh, ino, &absent);
                    kh_val(opendirh, k) = dir;
                    return k;
                }
                free(dir->filenames);
                free(dir->fileinos);
                free(dir);
            }
        } else {
            return k;
        }
    }

    return kh_end(opendirh);
}

void fatal_error(const char *message) {
    puts(message);
    exit(1);
}

static void smt_init(void *userdata, struct fuse_conn_info *conn) {

    filemap = calloc(MAX_FILES, sizeof(struct file_info));
    if (!filemap) {
        fatal_error("Couldn't allocate filemap!");
    }

    frmp.currfree = 1; //init to inode 1
    frmp.nextfr = calloc(MAX_FILES, sizeof(ino_t));
    if (!frmp.nextfr) {
        fatal_error("Couldn't allocate freemap!");
    }
    for (int i = 0; i < MAX_FILES; i++) {
        frmp.nextfr[i] = i+1;
    }

    dirh = kh_init(dirhash);
    opendirh = kh_init(opendirhash);
    lvisit.currindex = 0;
    lvisit.currvisit = 0;
    lvisit.visits = calloc(MAX_OPEN, sizeof(struct vst));
    if (!lvisit.visits) {
        fatal_error("Couldn't allocate last_visited!");
    }

    char *root = strdup("/");
    add_sysdirs(root, S_IFDIR | 0555);
    free(root);

    char *tags = strdup("_TAGS");
    add_sysdirs(tags, S_IFDIR | 0777);
    add_filetodir(filemap[ROOT].name, TAGS);
    free(tags);

    char *files = strdup("_FILES");
    add_sysdirs(files, S_IFDIR | 0777);
    add_filetodir(filemap[ROOT].name, FILES);
    free(files);

    char *home = strdup("_Home");
    add_sysdirs(home, S_IFDIR | 0777);
    add_filetodir(filemap[ROOT].name, HOME);
    free(files);
}

static void smt_destroy(void *userdata) {

    for (khint_t k = 0; k < kh_end(opendirh); ++k)
        if (kh_exist(opendirh, k)) {
            struct opendirinfo* dir = kh_val(opendirh, k);
            int i = 0;
            while (dir->filenames[i]) {
                free(dir->filenames[i]);
                i++;
            }
            free(dir->filenames);
            free(dir->fileinos);
            free(dir);
        }
    kh_destroy(opendirhash, opendirh);
    free(lvisit.visits);

    for (khint_t k = 0; k < kh_end(dirh); ++k)
        if (kh_exist(dirh, k)) {
            struct dirinfo* dir = kh_val(dirh, k);
            for (int i = 0; i < MAX_FCSIZE; i++) {
                struct fileino *next = dir->files[i].next;
                while (next) {
                    struct fileino *node = next;
                    next = next->next;
                    free(node);
                }
            }
            free(dir->files);
            free(dir);
            //free((char*)kh_key(dirh, k));
        }
    kh_destroy(dirhash, dirh);

    free(frmp.nextfr);
    for (int i = 1; i < MAX_FILES; i++) {
        if (filemap[i].ino) {
            free(filemap[i].name);
            free(filemap[i].data);
            for (int j = 0; j < MAX_DCSIZE; j++) {
                struct fileino *next = filemap[i].dir[j].next;
                while (next) {
                    struct fileino *node = next;
                    next = next->next;
                    free(node);
                }
            }
            free(filemap[i].dir);
        }
    }
    free(filemap);

    printf("smt_destroy: Finished cleanup\n");
}

static void dirbuf_add(fuse_req_t req, struct dirbuf *b, const char *name, fuse_ino_t ino)
{
	struct stat stbuf;
	size_t oldsize = b->size;

	b->size += fuse_add_direntry(req, NULL, 0, name, NULL, 0);
	b->p = (char *) realloc(b->p, b->size);
	memset(&stbuf, 0, sizeof(stbuf));
	stbuf.st_ino = ino;
	fuse_add_direntry(req, b->p + oldsize, b->size - oldsize, name, &stbuf, b->size);
}

void refreshdir(fuse_req_t req, struct dirbuf *b, ino_t ino, int addbuff) {

    printf("refreshdir in directory -> %ld\n", ino);

    struct dirinfo *dir = NULL;
    khint_t k;
    k = kh_get(dirhash, dirh, filemap[ino].name);
    if (k != kh_end(dirh)) {
        dir = kh_val(dirh, k);
    }

    k = add_opendir(ino);

    if (k != kh_end(opendirh) && dir != NULL) {
        khash_t(filenamehash) *fnh = kh_init(filenamehash);
        khint_t k1;
        int absent;

        struct opendirinfo *opendir = kh_val(opendirh, k);
        lvisit.visits[opendir->index].visit = lvisit.currvisit++;
        memset(opendir->fileinos, 0, MAX_FILES*sizeof(ino_t));

        for (int i = 0; i < MAX_FCSIZE; i++) {
            if (dir->files[i].ino) {
                struct fileino *node = &dir->files[i];
                while (node) {
                    struct file_info f = filemap[node->ino];

                    k1 = kh_get(filenamehash, fnh, f.name);
                    if (k1 != kh_end(fnh)) {
                        kh_value(fnh, k1) = 1;
                    } else {
                        k1 = kh_put(filenamehash, fnh, f.name, &absent);
                        kh_value(fnh, k1) = 0;
                    }

                    node = node->next;
                }
            }
        }

        int p = 0;
        for (int i = 0; i < MAX_FCSIZE; i++) {
            if (dir->files[i].ino) {
                struct fileino *node = &dir->files[i];
                while (node) {
                    struct file_info f = filemap[node->ino];
                    printf("refreshdir: found file -> %ld at %d\n", node->ino, i);

                    k1 = kh_get(filenamehash, fnh, f.name);
                    if (kh_value(fnh, k1) == 1) {
                        char *name;
                        int length = snprintf(NULL, 0, "%ld", f.ino);
                        char app[length+1];
                        if ((name = malloc(strlen(f.name) + length + 2)) != NULL) {
                            name[0] = '\0';
                            sprintf(app, "%ld", f.ino);
                            strcat(name, f.name);
                            strcat(name, ":");
                            strcat(name, app);

                            if (!opendir->filenames[p]) {
                                opendir->filenames[p] = (char *)malloc(MAX_FILENAME_LEN);
                                if (!opendir->filenames[p]) {
                                    printf("refreshdir: filename malloc fail -> %ld at %d\n", node->ino, i);
                                    continue;
                                }
                            }
                            strncpy(opendir->filenames[p], name, strlen(name));
                            opendir->filenames[p][strlen(name)] = '\0';
                            free(name);
                        } else {
                            if (!opendir->filenames[p]) {
                                opendir->filenames[p] = (char *)malloc(MAX_FILENAME_LEN);
                                if (!opendir->filenames[p]) {
                                    printf("refreshdir: filename malloc fail -> %ld at %d\n", node->ino, i);
                                    continue;
                                }
                            }
                            strncpy(opendir->filenames[p], f.name, strlen(f.name));
                            opendir->filenames[p][strlen(f.name)] = '\0';
                        }
                    } else {
                        if (!opendir->filenames[p]) {
                            opendir->filenames[p] = (char *)malloc(MAX_FILENAME_LEN);
                            if (!opendir->filenames[p]) {
                                printf("refreshdir: filename malloc fail -> %ld at %d\n", node->ino, i);
                                continue;
                            }
                        }
                        strncpy(opendir->filenames[p], f.name, strlen(f.name));
                        opendir->filenames[p][strlen(f.name)] = '\0';
                    }

                    opendir->fileinos[p] = f.ino;
                    if (addbuff) {
                        printf("Adding entry for filename -> %s | inode -> %ld\n", opendir->filenames[p], opendir->fileinos[p]);
                        dirbuf_add(req, b, opendir->filenames[p], opendir->fileinos[p]);
                    }

                    node = node->next;
                    p++;
                }
            }
        }
        kh_destroy(filenamehash, fnh);
    }
}

static int reply_buf_limited(fuse_req_t req, const char *buf, size_t bufsize, off_t off, size_t maxsize)
{
    if (off < bufsize) {
        return fuse_reply_buf(req, buf + off, min(bufsize - off, maxsize));
    } else {
        return fuse_reply_buf(req, NULL, 0);
    }
}

int dirset(const char* name, const char *pos) {

    char *dir1 = (char *)malloc((pos-name)+1);
    strncpy(dir1, name, pos-name);
    dir1[pos-name] = '\0';
    char *dir2 = (char *)malloc(strlen(name)-(pos-name));
    strncpy(dir2, name+(pos-name)+2, strlen(name)-(pos-name)-1);
    dir2[strlen(name)-(pos-name)-1] = '\0';

    struct dirinfo *d1 = NULL;
    khint_t k = kh_get(dirhash, dirh, dir1);
    if (k != kh_end(dirh)) {
        d1 = kh_val(dirh, k);
    } else {
        return 0;
    }
    struct dirinfo *d2 = NULL;
    k = kh_get(dirhash, dirh, dir2);
    if (k != kh_end(dirh)) {
        d2 = kh_val(dirh, k);
    }

    free(dir1);
    free(dir2);
    if (d1 && d2) {
        char bmap1[BITNSLOTS(MAX_FILES)];
        memset(bmap1, 0, BITNSLOTS(MAX_FILES));
        for (int i = 0; i < MAX_FCSIZE; i++) {
            if (d1->files[i].ino) {
                struct fileino *node = &d1->files[i];
                while (node) {
                    BITSET(bmap1, (int)node->ino);
                    node = node->next;
                }
            }
        }
        char bmap2[BITNSLOTS(MAX_FILES)];
        memset(bmap2, 0, BITNSLOTS(MAX_FILES));
        for (int i = 0; i < MAX_FCSIZE; i++) {
            if (d2->files[i].ino) {
                struct fileino *node = &d2->files[i];
                while (node) {
                    BITSET(bmap2, (int)node->ino);
                    node = node->next;
                }
            }
        }

        char bresmap[BITNSLOTS(MAX_FILES)];
        memset(bresmap, 0, BITNSLOTS(MAX_FILES));
        if (name[(pos-name)+1] == '&') {
            for (int i = 1; i < BITNSLOTS(MAX_FILES); i++) {
                bresmap[i] = BITTEST(bmap1, i) && BITTEST(bmap2, i);
            }
        } else if (name[(pos-name)+1] == '|') {
            for (int i = 1; i < BITNSLOTS(MAX_FILES); i++) {
                bresmap[i] = BITTEST(bmap1, i) || BITTEST(bmap2, i);
            }
        } else if (name[(pos-name)+1] == '^') {
            for (int i = 1; i < BITNSLOTS(MAX_FILES); i++) {
                bresmap[i] = !BITTEST(bmap1, i) != !BITTEST(bmap2, i);
            }
        } else if (name[(pos-name)+1] == '~') {
            for (int i = 1; i < BITNSLOTS(MAX_FILES); i++) {
                bresmap[i] = BITTEST(bmap1, i) && !BITTEST(bmap2, i);
            }
        }

        ino_t ino = add_file(0x0, 0x0, name, S_IFDIR | 0777);

        if (ino) {
            for (int i = 1; i < BITNSLOTS(MAX_FILES); i++) {
                if (bresmap[i]) {
                    add_filetodir(name, i);
                }
            }
        }

        return ino;
    }
    return 0;
}

static void smt_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
    struct fuse_entry_param e;
    khint_t k;
    struct file_info *f = NULL;

    memset(&e, 0, sizeof(e));

    k = add_opendir(parent);

    if (k != kh_end(opendirh)) {
        struct opendirinfo *opendir = kh_val(opendirh, k);
        int i = 0;
        while (opendir->fileinos[i]) {
            if (!strncmp(opendir->filenames[i], name, strlen(name))) {
                f = &filemap[opendir->fileinos[i]];
                break;
            }
            i++;
        }
    } else if (!strncmp("..", name, strlen(".."))) {
        f = &filemap[ROOT];
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

        fuse_reply_entry(req, &e);
        return;
    }
    fuse_reply_err(req, ENOENT);
}

static void smt_forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup) {

    if (filemap[ino].ino) {
        if (filemap[ino].nlink == 0 || ((filemap[ino].mode & S_IFMT) == S_IFDIR && filemap[ino].nlink == 1)) {
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
	(void) fi;
    memset(&stbuf, 0, sizeof(stbuf));

    if (filemap[ino].ino) {
        struct file_info f = filemap[ino];
        stbuf.st_ino = ino;
        stbuf.st_mode = f.mode;
        stbuf.st_nlink = f.nlink;
        stbuf.st_size = f.size;
        stbuf.st_atim = f.atime;
        stbuf.st_ctim = f.ctime;
        stbuf.st_mtim = f.mtime;
        fuse_reply_attr(req, &stbuf, 1.0);
    } else {
        fuse_reply_err(req, ENOENT);
    }
}

static void smt_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr, int to_set, struct fuse_file_info *fi)
{
    struct stat stbuf;

    if ((filemap[ino].mode & S_IFMT) == S_IFDIR) {
        fuse_reply_err(req, EISDIR);
        return;
    }

    memset(&stbuf, 0, sizeof(stbuf));
    stbuf.st_ino = ino;
    stbuf.st_nlink = filemap[ino].nlink;

    if (to_set & FUSE_SET_ATTR_MODE) {
        stbuf.st_mode = attr->st_mode;
    } else {
        stbuf.st_mode = filemap[ino].mode;
    }
    if (to_set & FUSE_SET_ATTR_SIZE) {
        stbuf.st_size = attr->st_size;
    } else {
        stbuf.st_size = filemap[ino].size;
    }
    if (to_set & FUSE_SET_ATTR_ATIME) {
        stbuf.st_atime = attr->st_atime;
    }
    if (to_set & FUSE_SET_ATTR_MTIME) {
        stbuf.st_mtime = attr->st_mtime;
    }
    if (to_set & FUSE_SET_ATTR_CTIME) {
        stbuf.st_ctime = attr->st_ctime;
    }

    fuse_reply_attr(req, &stbuf, 1.0);
    return;
}

void smt_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
                     struct fuse_file_info *fi)
{
    (void)fi;
    struct dirbuf b;

    memset(&b, 0, sizeof(b));

    dirbuf_add(req, &b, ".", ino);
    dirbuf_add(req, &b, "..", ino);
    refreshdir(req, &b, ino, 1);

    reply_buf_limited(req, b.p, b.size, off, size);
    free(b.p);
}

static void smt_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode) {

    struct fuse_entry_param e;
    memset(&e, 0, sizeof(e));

    khint_t k = kh_get(dirhash, dirh, name); //make sure the name isn't already present

    if (frmp.currfree < MAX_FILES && k == kh_end(dirh)) {
        ino_t ino;

        char const *pos = strchr(name, '\\');
        if (pos != NULL && (pos-name)+1 != strlen(name)) {
            ino = dirset(name, pos);
        } else {
            ino = add_file(0x0, 0x0, name, S_IFDIR | 0777);
        }

        if (ino) {
            if (parent != TAGS) {
                add_filetodir(filemap[parent].name, ino);
            }

            e.ino = ino;
            e.attr.st_ino = ino;
            e.attr.st_mode = filemap[ino].mode;
            e.attr.st_nlink = filemap[ino].nlink;
            e.attr.st_size = filemap[ino].size;

            fuse_reply_entry(req, &e);
            return;
        }
    }

    fuse_reply_err(req, ENOSPC);
}

static void smt_rename(fuse_req_t req, fuse_ino_t parent, const char *name, fuse_ino_t newparent, const char *newname, unsigned int flags)
{
	int res = ENOENT;

	if (flags || parent == ROOT) {
		fuse_reply_err(req, EINVAL);
		return;
	}

    khint_t k;
    k = add_opendir(parent);

    if (k != kh_end(opendirh)) {
        struct opendirinfo *opendir = kh_val(opendirh, k);
        int i = 0;
        while (opendir->fileinos[i]) {
            if (!strncmp(opendir->filenames[i], name, strlen(name))) {
                struct file_info *f = &filemap[opendir->fileinos[i]];
                struct dirinfo *olddir = NULL;

                if ((f->mode & S_IFMT) == S_IFDIR) {
                    k = kh_get(dirhash, dirh, newname);
                    if (k != kh_end(dirh)) {
                        fuse_reply_err(req, EINVAL);
                        return;
                    }

                    k = kh_get(dirhash, dirh, name);
                    if (k != kh_end(dirh)) {
                        olddir = kh_value(dirh, k);
                    }
                }

                strncpy(f->name, newname, strlen(newname));
                f->name[strlen(newname)] = 0x0;

                if ((f->mode & S_IFMT) == S_IFDIR) {
                    struct dirinfo *newdir = add_directory(olddir->ino, f->name);
                    free(newdir->files);
                    newdir->files = olddir->files;
                    free(olddir);
                    kh_del(dirhash, dirh, k);
                }

                strncpy(opendir->filenames[i], newname, strlen(newname));
                opendir->filenames[i][strlen(newname)] = 0x0;

                for (int i = 0; i < MAX_DCSIZE; i++) {
                    if (f->dir[i].ino) {
                        struct fileino *node = &f->dir[i];
                        while (node) {
                            k = kh_get(opendirhash, opendirh, node->ino);
                            if (k != kh_end(opendirh)) {
                                refreshdir(NULL, NULL, node->ino, 0);
                            }
                            node = node->next;
                        }
                    }
                }

                if (parent != newparent) {
                    add_filetodir(filemap[newparent].name, f->ino);
                }
                clock_gettime(CLOCK_REALTIME, &f->ctime);
                clock_gettime(CLOCK_REALTIME, &filemap[parent].ctime);
                clock_gettime(CLOCK_REALTIME, &filemap[parent].mtime);

                res = 0;
                break;
            }
            i++;
        }
    }

	fuse_reply_err(req, res);
}

static void smt_create(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode, struct fuse_file_info *fi)
{
	int newfd;
    struct fuse_entry_param e;
    memset(&e, 0, sizeof(e));

    printf("create called with filename %s and mode %d\n", name, mode);

    if (frmp.currfree < MAX_FILES && ((mode & S_IFMT) != S_IFDIR) && ((filemap[parent].mode & S_IFMT) == S_IFDIR)) {
        ino_t ino = add_file(strlen("dummy data\n"), strdup("dummy data\n"), name, S_IFREG | 0777);

        if (parent != FILES) {
            add_filetodir(filemap[parent].name, ino);
        }

        e.ino = ino;
        e.attr.st_ino = ino;
        e.attr.st_mode = filemap[ino].mode;
        e.attr.st_nlink = filemap[ino].nlink;
        e.attr.st_size = filemap[ino].size;

        char *filepath = malloc(PATH_MAX);
        if (filepath) {
            strcat(filepath, storage);
            strcat(filepath, "/");
            int length = snprintf(NULL, 0, "%ld", ino);
            char *strino = malloc(length+1);
            sprintf(strino, "%ld", ino);
            strcat(filepath, strino);

            newfd = open(filepath, O_WRONLY | O_CREAT | S_IFREG, 0777);
            if (newfd) {
                fi->fh = newfd;
                filemap[ino].dirty = 1;
                fuse_reply_create(req, &e, fi);
            } else {
                fuse_reply_err(req, errno);
            }
            free(filepath);
        }
        return;
    }

    fuse_reply_err(req, EPERM);
}

static void smt_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi)
{
    (void) fi;

    if ((filemap[ino].mode & S_IFMT) == S_IFDIR) {
        fuse_reply_err(req, EISDIR);
    } else if (filemap[ino].ino) {
        reply_buf_limited(req, filemap[ino].data, filemap[ino].size, off, size);
        return;
    }
    fuse_reply_err(req, ENOENT);
}

static void smt_unlink(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	int res = ENOENT;
    khint_t k;

    k = add_opendir(parent);

    if (k != kh_end(opendirh)) {
        struct opendirinfo *opendir = kh_val(opendirh, k);
        int i = 0;
        while (opendir->fileinos[i]) {
            if (!strncmp(opendir->filenames[i], name, strlen(name))) {
                struct file_info f = filemap[opendir->fileinos[i]];
                remove_filefromdir(filemap[parent].name, f.ino);

                if (parent == FILES) { //if unlinking from _FILES, unlink from everywhere and free file
                    remove_file(f.ino);
                } else {
                    clock_gettime(CLOCK_REALTIME, &filemap[f.ino].ctime);
                }
                res = 0;
                break;
            }
            i++;
        }
    }

	fuse_reply_err(req, res);
}

static void smt_rmdir(fuse_req_t req, fuse_ino_t parent, const char *name) {
    khint_t k;
    int res = EPERM;

    k = kh_get(dirhash, dirh, name);
    if (k != kh_end(dirh)) {
        struct dirinfo *dir = kh_value(dirh, k);

        printf("nlink: %ld\n", filemap[dir->ino].nlink);
        if (dir->ino > SYSDIR && filemap[dir->ino].nlink > 0) {
            remove_filefromdir(filemap[parent].name, dir->ino);

            if (parent == TAGS) { //if unlinking from /, unlink from everywhere and free file
                remove_file(dir->ino);
            } else {
                clock_gettime(CLOCK_REALTIME, &filemap[dir->ino].ctime);
            }
            res = 0;
        }
    }
    fuse_reply_err(req, res);
}

static void smt_write(fuse_req_t req, fuse_ino_t ino, const char *buf, size_t size, off_t off, struct fuse_file_info *fi)
{
    printf("write called on the file %ld\n", ino);
    printf("offset = %lu and size=%zu\n", off, size);
    if ((filemap[ino].mode & S_IFMT) == S_IFDIR) {
        fuse_reply_err(req, EISDIR);
    } else if (ino < frmp.currfree) {
        if (filemap[ino].size == 0) {
            filemap[ino].data = malloc(size + off);
        } else {
            filemap[ino].data = realloc(filemap[ino].data, off + size);
        }
        if (!filemap[ino].data) {
            fuse_reply_err(req, ENOMEM);
            return;
        }

        filemap[ino].size = off + size;
        memcpy(filemap[ino].data + off, buf, size);
        filemap[ino].dirty = 1;
        clock_gettime(CLOCK_REALTIME, &filemap[ino].ctime);
        clock_gettime(CLOCK_REALTIME, &filemap[ino].mtime);

        fuse_reply_write(req, size);
        return;
    }
}

static void smt_flush(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	int res;
	if (filemap[ino].dirty) {
        write(fi->fh, filemap[ino].data, filemap[ino].size);
        filemap[ino].dirty = 0;
	}
	res = close(dup(fi->fh));
	fuse_reply_err(req, res == -1 ? errno : 0);
}

static void smt_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	(void) ino;

	close(fi->fh);
	fuse_reply_err(req, 0);
}

/*static void smt_statfs(fuse_req_t req, fuse_ino_t ino)
{
	int res;
	struct statvfs stbuf;

	res = statvfs(devfile, &stbuf);
	if (res == -1)
		fuse_reply_err(req, errno);
	else
		fuse_reply_statfs(req, &stbuf);
}*/

static void smt_listxattr(fuse_req_t req, fuse_ino_t ino, size_t size)
{
	char *value = NULL;
    ssize_t ret = 0;
    struct file_info f = filemap[ino];

    if (size) {
        value = (char *)malloc(size);
        if (!value) {
            fuse_reply_err(req, ENOMEM);
            return;
        }
        char *p = value;
        for (int i = 0; i < MAX_DCSIZE; i++) {
            if (f.dir[i].ino) {
                struct fileino *node = &f.dir[i];
                while (node) {
                    p = memccpy(p, filemap[node->ino].name, '\0', strlen(filemap[node->ino].name)+1);
                    node = node->next;
                }
            }
        }
		fuse_reply_buf(req, value, size);
    } else {
        for (int i = 0; i < MAX_DCSIZE; i++) {
            if (f.dir[i].ino) {
                struct fileino *node = &f.dir[i];
                while (node) {
                    ret += strlen(filemap[f.dir[i].ino].name)+1;
                    node = node->next;
                }
            }
        }
		fuse_reply_xattr(req, ret);
    }
    free(value);
}

static void smt_getxattr(fuse_req_t req, fuse_ino_t ino, const char *name, size_t size)
{

    if (!strncmp(name, "security.capability", strlen(name))) {
        fuse_reply_err(req, EOPNOTSUPP);
        return;
    }

    if (size) {
        khint_t k;
        k = kh_get(dirhash, dirh, name);
        if (k != kh_end(dirh)) {
            fuse_reply_buf(req, name, size);
        } else {
            fuse_reply_err(req, ENOENT);
        }
    } else {
        fuse_reply_xattr(req, strlen(name)+1);
    }
}

int recursive_dir(ino_t dirino, ino_t ino) {
    if (dirino == ino) {
        return EPERM;
    }

    int saverr = 0;
    for (int i = 0; i < MAX_DCSIZE; i++) {
        if (filemap[dirino].dir[i].ino) {
            struct fileino *node = &filemap[dirino].dir[i];
            while (node) {
                saverr = recursive_dir(node->ino, ino);
                if (saverr) {
                    return saverr;
                }
                node = node->next;
            }
        }
    }

    return saverr;
}

static void smt_setxattr(fuse_req_t req, fuse_ino_t ino, const char *name, const char *value, size_t size, int flags)
{
    int saverr = EPERM;

    if (ino < SYSDIR) { //don't allow tagging system directories
        fuse_reply_err(req, saverr);
        return;
    }

    khint_t k;
    k = kh_get(dirhash, dirh, name);

    if (k != kh_end(dirh)) {
        struct dirinfo *dir = kh_value(dirh, k);
        if (filemap[ino].dir[(dir->ino-1)%MAX_DCSIZE].ino) { //check if dir being added is already present
            struct fileino *node = &filemap[ino].dir[(dir->ino-1)%MAX_DCSIZE];
            while (node) {
                if (filemap[ino].dir[(dir->ino-1)%MAX_DCSIZE].ino == dir->ino) {
                    fuse_reply_err(req, saverr);
                    return;
                }
                node = node->next;
            }
        }
        if ((filemap[ino].mode & S_IFMT) == S_IFDIR) {
            saverr = recursive_dir(dir->ino, ino); //check for A->..->A circular relation
            if (saverr) {
                fuse_reply_err(req, saverr);
                return;
            }
        }
        saverr = add_filetodir(name, ino);
    } else {
        add_file(0x0, 0x0, name, S_IFDIR | 0777);
        saverr = add_filetodir(name, ino);
    }

    fuse_reply_err(req, saverr);
}

static void smt_removexattr(fuse_req_t req, fuse_ino_t ino, const char *name) {
    int saverr = EPERM;
    khint_t k;

    if (ino < 3) { //don't allow removal from _TAGS or _FILES via xattr
        fuse_reply_err(req, saverr);
        return;
    }

    k = kh_get(dirhash, dirh, name);
    if (k != kh_end(dirh)) {
        struct dirinfo *dir = kh_value(dirh, k);
        if (filemap[ino].dir[(dir->ino-1)%MAX_DCSIZE].ino) {
            struct fileino *node = &filemap[ino].dir[(dir->ino-1)%MAX_DCSIZE];
            while (node) {
                if (node->ino == dir->ino) {
                    remove_filefromdir(name, ino);
                    saverr = 0;
                    break;
                }
                node = node->next;
            }
        }
    }
    fuse_reply_err(req, saverr);
}

static struct fuse_lowlevel_ops operations = {
    .init = smt_init,
    .destroy = smt_destroy,
    .lookup = smt_lookup,
    .forget = smt_forget,
    .getattr = smt_getattr,
    .setattr = smt_setattr,
    .readdir = smt_readdir,
    .read = smt_read,
    .mkdir = smt_mkdir,
    .rename = smt_rename,
    .create = smt_create,
    .unlink = smt_unlink,
    .rmdir = smt_rmdir,
    .write = smt_write,
    .flush = smt_flush,
    .release = smt_release,
    .listxattr = smt_listxattr,
    .getxattr = smt_getxattr,
    .setxattr = smt_setxattr,
    .removexattr = smt_removexattr,
};

int main(int argc, char **argv)
{
    int retval = 0;
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct fuse_cmdline_opts opts;
    struct fuse_session *se;

    if (fuse_parse_cmdline(&args, &opts)) {
        return 1;
    }
    if (opts.show_help) {
        printf("Usage: %s [options] <mountpoint>\n", argv[0]);
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
        printf("Usage: %s [options] <mountpoint>\n", argv[0]);
        return 1;
    }

    devfile = realpath(opts.mountpoint, NULL);
    storage = "/home/k/Downloads/fuse-3.17.2/example/storage";

    se = fuse_session_new(&args, &operations, sizeof(operations), NULL);
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
    fuse_opt_free_args(&args);
    return retval;
}


