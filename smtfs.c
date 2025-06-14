#define FUSE_USE_VERSION FUSE_MAKE_VERSION(3, 17)

#define MAX_FILES 1000
#define MAX_CSIZE 100
#define MAX_DIR 100
#define MAX_OPEN 100
#define MAX_FILENAME_LEN 256

#define min(x, y) ((x) < (y) ? (x) : (y))

#include <fuse3/fuse_lowlevel.h>
#include "khash.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/xattr.h>

const char *devfile = NULL;

struct fileino {
    ino_t ino;
    struct fileino *next;
};

struct file_info
{
    ino_t ino;
    char *name;
    size_t size;
    char *data;
    mode_t mode;
    nlink_t nlink;
    uint64_t fd;
    int ffree;
    ino_t *dir; //MAX_DIR cut of files
};

struct file_info *filemap;

struct freemap {
    int currfree;
    ino_t *nextfr;
};

struct freemap frmp;

struct dirinfo {
    ino_t ino;
    bool dironly;
    struct fileino *files; //MAX_CSIZE cut of files
};

KHASH_MAP_INIT_STR(dirhash, struct dirinfo*)
khash_t(dirhash) *dirh;

struct dirinfo* add_directory(ino_t ino, const char* name, bool dironly) {

    struct dirinfo *dir = NULL;
    khint_t k;
    int absent;

    k = kh_get(dirhash, dirh, name);
    if (k == kh_end(dirh)) {
        dir = malloc(sizeof(struct dirinfo*));
        dir->ino = ino;
        dir->dironly = dironly;
        dir->files = calloc(MAX_CSIZE, sizeof(struct fileino));
        k = kh_put(dirhash, dirh, filemap[ino].name, &absent);
        kh_val(dirh, k) = dir;
        //if (absent) kh_key(dirh, k) = strdup(dir->name);
    } else {
        dir = kh_val(dirh, k);
    }

    return dir;
}

int add_filetodir(const char* name, ino_t ino) {

    struct dirinfo *dir;
    khint_t k;
    int i;

    k = kh_get(dirhash, dirh, name);
    if (k != kh_end(dirh)) {
        dir = kh_val(dirh, k);
        if (!dir->files[(ino-1)%MAX_CSIZE].ino) {
            dir->files[(ino-1)%MAX_CSIZE].ino = ino;
            dir->files[(ino-1)%MAX_CSIZE].next = NULL;

            filemap[ino].dir[filemap[ino].ffree] = dir->ino;
            for (i = filemap[ino].ffree+1; i < MAX_DIR; i++) {
                if (!filemap[ino].dir[i]) {
                    filemap[ino].ffree = i;
                    break;
                }
            }
            if (i == MAX_DIR) {
                filemap[ino].ffree = MAX_DIR;
            }

            filemap[ino].nlink++;
            printf("adding ino %ld to %ld\n", ino, dir->ino);
            return 0;
        } else {
            struct fileino *node = &dir->files[(ino-1)%MAX_CSIZE];
            while (node->next != NULL) {
                node = node->next;
            }
            node->next = malloc(sizeof(struct fileino));
            node->next->ino = ino;
            node->next->next = NULL;

            filemap[ino].dir[filemap[ino].ffree] = dir->ino;
            for (i = filemap[ino].ffree+1; i < MAX_DIR; i++) {
                if (!filemap[ino].dir[i]) {
                    filemap[ino].ffree = i;
                    break;
                }
            }
            if (i == MAX_DIR) {
                filemap[ino].ffree = MAX_DIR;
            }

            filemap[ino].nlink++;
            printf("adding ino %ld to %ld\n", ino, dir->ino);
            return 0;
        }
    }

    return EPERM;
}

int remove_filefromdir(const char *name, ino_t ino) {
    struct dirinfo *dir;
    khint_t k;

    k = kh_get(dirhash, dirh, name);
    if (k != kh_end(dirh)) {
        dir = kh_val(dirh, k);
        if (dir->files[(ino-1)%MAX_CSIZE].ino == ino) {
            if (dir->files[(ino-1)%MAX_CSIZE].next) {
                struct fileino *node = dir->files[(ino-1)%MAX_CSIZE].next;
                dir->files[(ino-1)%MAX_CSIZE] = *(dir->files[(ino-1)%MAX_CSIZE].next);
                free(node);
            } else {
                dir->files[(ino-1)%MAX_CSIZE].ino = 0;
            }
            for (int j = 0; j < MAX_DIR; j++) {
                if (filemap[ino].dir[j] == dir->ino) {
                    filemap[ino].dir[j] = 0;
                    filemap[ino].ffree = j;
                    filemap[ino].nlink--;
                    break;
                }
            }
        } else {
            struct fileino *prev = &dir->files[(ino-1)%MAX_CSIZE];
            struct fileino *node = prev->next;
            while (node) {
                if (node->ino == ino) {
                    prev->next = node->next;
                    free(node);
                    for (int j = 0; j < MAX_DIR; j++) {
                        if (filemap[ino].dir[j] == dir->ino) {
                            filemap[ino].dir[j] = 0;
                            filemap[ino].ffree = j;
                            filemap[ino].nlink--;
                            break;
                        }
                    }
                    break;
                }
                prev = node;
                node = node->next;
            }
        }
    }
    printf("nlink after remove_filefromdir: %ld\n", filemap[ino].nlink);

    return 0;
}

int remove_directory(const char* name) {
    struct dirinfo *dir = NULL;
    khint_t k;

    k = kh_get(dirhash, dirh, name);
    if (k != kh_end(dirh)) {
        dir = kh_val(dirh, k);
        for (int i = 0; i < MAX_CSIZE; i++) {
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
        kh_del(dirhash, dirh, k);
    }
    return 0;
}

int add_file(size_t size, char *data, const char *name, mode_t mode) {

    if (frmp.currfree < MAX_FILES) {
        filemap[frmp.currfree].ino = frmp.currfree;
        filemap[frmp.currfree].name = (char *)malloc(MAX_FILENAME_LEN);
        strncpy(filemap[frmp.currfree].name, name, strlen(name)+1);
        filemap[frmp.currfree].name[strlen(name)] = 0x0;
        filemap[frmp.currfree].size = size;
        filemap[frmp.currfree].data = data;
        filemap[frmp.currfree].mode = mode | 0777;
        filemap[frmp.currfree].fd = 0;
        filemap[frmp.currfree].ffree = 0;
        filemap[frmp.currfree].dir = calloc(MAX_DIR, sizeof(ino_t));
        if ((mode & S_IFMT) == S_IFDIR) {
            filemap[frmp.currfree].nlink = 1;
            add_directory(frmp.currfree, name, 0);
            add_filetodir(filemap[1].name, frmp.currfree); //root directory contains all directories (bar itself)
        } else {
            filemap[frmp.currfree].nlink = 0;
            add_filetodir(filemap[2].name, frmp.currfree); //* directory contains all regular files
        }

        ino_t ino = frmp.currfree;
        frmp.currfree = frmp.nextfr[frmp.currfree];
        return ino;
    }
    return -1;
}

int remove_file(ino_t ino) {

    for (int i = 0; i < MAX_DIR; i++) {
        if (filemap[ino].dir[i]) {
            remove_filefromdir(filemap[filemap[ino].dir[i]].name, ino);
        }
    }
    if ((filemap[ino].mode & S_IFMT) == S_IFDIR) {
        remove_directory(filemap[ino].name);
        filemap[ino].nlink--;
    }

    free(filemap[ino].name);
    free(filemap[ino].data);
    free(filemap[ino].dir);
    filemap[ino].ffree = 0;
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

struct opendirinfo {
    ino_t ino;
    ino_t *fileinos;
    char **filenames; //filename-inode hashmap
};

struct visit_freq {
    ino_t ino;
    int visits;
};

KHASH_MAP_INIT_INT(opendirhash, struct opendirinfo*)
khash_t(opendirhash) *opendirh;
struct visit_freq *vfreq;

khint_t add_opendir(ino_t ino) {

    khint_t k;
    int absent;

    k = kh_get(opendirhash, opendirh, ino);
    if (k == kh_end(opendirh)) {
        if (kh_size(opendirh) >= MAX_OPEN) {

        }
        struct opendirinfo *dir = malloc(sizeof(struct opendirinfo*));
        dir->ino = ino;
        dir->fileinos = calloc(MAX_FILES, sizeof(ino_t));
        dir->filenames = malloc(MAX_FILES*sizeof(int *));
        for (int i = 0; i < MAX_FILES; i++) {
            dir->filenames[i] = (char *)malloc(MAX_FILENAME_LEN);
        }
        vfreq[ino].ino = ino;
        vfreq[ino].visits = 1;
        k = kh_put(opendirhash, opendirh, ino, &absent);
        kh_val(opendirh, k) = dir;
    }

    return k;
}

void remove_opendir(ino_t ino) {

}

void fatal_error(const char *message) {
    puts(message);
    exit(1);
}

static void smt_init(void *userdata, struct fuse_conn_info *conn) {

    filemap = calloc(MAX_FILES, sizeof(struct file_info));

    frmp.currfree = 1; //init to inode 1
    frmp.nextfr = calloc(MAX_FILES, sizeof(ino_t));
    for (int i = 0; i < MAX_FILES; i++) {
        frmp.nextfr[i] = i+1;
    }

    dirh = kh_init(dirhash);
    opendirh = kh_init(opendirhash);
    vfreq = calloc(MAX_FILES, sizeof(struct visit_freq));

    add_file(0x0, 0x0, strdup("/"), S_IFDIR);

    //root directory shouldn't contain itself
    filemap[1].dir[0] = 0;
    filemap[1].ffree = 0;
    khint_t k = kh_get(dirhash, dirh, filemap[1].name);
    if (k != kh_end(dirh)) {
        struct dirinfo *dir = kh_val(dirh, k);
        dir->dironly = 1;
        dir->files[0].ino = 0;
    } else {
        fatal_error("Couldn't find root directory in hash");
    }

    add_file(0, 0x0, strdup("*"), S_IFDIR);
}

static void smt_destroy(void *userdata) {

    for (khint_t k = 0; k < kh_end(opendirh); ++k)
        if (kh_exist(opendirh, k)) {
            struct opendirinfo* dir = kh_val(opendirh, k);
            free(dir->fileinos);
            for (int i = 0; i < MAX_FILES; i++) {
                free(dir->filenames[i]);
            }
            free(dir->filenames);
            free(dir);
        }
    kh_destroy(opendirhash, opendirh);
    free(vfreq);

    for (khint_t k = 0; k < kh_end(dirh); ++k)
        if (kh_exist(dirh, k)) {
            struct dirinfo* dir = kh_val(dirh, k);
            for (int i = 0; i < MAX_CSIZE; i++) {
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
            free(filemap[i].dir);
        }
    }
    free(filemap);

    printf("smt_destroy: Finished cleanup\n");
}

struct dirbuf {
	char *p;
	size_t size;
};

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
    // if ino > max_file * 10 its a set op
    struct dirinfo *dir = NULL;
    khint_t k;
    k = kh_get(dirhash, dirh, filemap[ino].name);
    if (k != kh_end(dirh)) {
        dir = kh_val(dirh, k);
    }

    k = add_opendir(ino);

    if (k != kh_end(opendirh) && dir != NULL) {
        struct opendirinfo *opendir = kh_val(opendirh, k);
        memset(opendir->fileinos, 0, MAX_FILES*sizeof(ino_t));
        int p = 0;
        for (int i = 0; i < MAX_CSIZE; i++) {
            if (dir->files[i].ino) {
                struct fileino *node = &dir->files[i];
                while (node) {
                    struct file_info f = filemap[node->ino];
                    printf("refreshdir: found file -> %ld at %d\n", node->ino, i);
                    char *name;
                    char app[3] = "~0";
                    if ((name = malloc(MAX_FILENAME_LEN)) != NULL){
                        int k = 1;
                        for (int j = 0; j < i; j++) {
                            if (dir->files[j].ino) {
                                struct fileino *nodej = &dir->files[j];
                                while (nodej) {
                                    if (!strncmp(filemap[nodej->ino].name, f.name, strlen(f.name))) {
                                        name[0] = '\0';
                                        app[1] = k + '0';
                                        strcat(name, f.name);
                                        strcat(name, app);
                                        k++;
                                    }
                                    nodej = nodej->next;
                                }
                            }
                        }
                        if (app[1] != '0') {
                            strncpy(opendir->filenames[p], name, strlen(name));
                            opendir->filenames[p][strlen(name)] = '\0';
                        } else {
                            strncpy(opendir->filenames[p], f.name, strlen(f.name));
                            opendir->filenames[p][strlen(f.name)] = '\0';
                        }
                        free(name);
                    } else {
                        strcpy(opendir->filenames[p], f.name);
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
    }
}

static int reply_buf_limited(fuse_req_t req, const char *buf, size_t bufsize, off_t off, size_t maxsize)
{
    if (off < bufsize)
        return fuse_reply_buf(req, buf + off,
                              min(bufsize - off, maxsize));
    else
        return fuse_reply_buf(req, NULL, 0);
}

void dirset(const char* name, const char *pos) {

    char *dir1 = (char *)malloc((pos-name)+1);
    strncpy(dir1, name, pos-name);
    dir1[pos-name] = '\0';
    char *dir2 = (char *)malloc(strlen(name)-(pos-name));
    strncpy(dir2, name+(pos-name)+2, strlen(name)-(pos-name)-1);
    dir2[strlen(name)-(pos-name)-1] = '\0';

    struct dirinfo *d1;
    khint_t k = kh_get(dirhash, dirh, dir1);
    if (k != kh_end(dirh)) {
        d1 = kh_val(dirh, k);
        printf("%s\n", filemap[d1->ino].name);
    }
    struct dirinfo *d2;
    k = kh_get(dirhash, dirh, dir2);
    if (k != kh_end(dirh)) {
        d2 = kh_val(dirh, k);
        printf("%s\n", filemap[d2->ino].name);
    }

    char map[MAX_FILES] = {0};
    for (int i = 0; i < MAX_FILES; i++) {
        if (!d1->files[i].ino) //and nodes
            map[d1->files[i].ino]++;
    }
    for (int i = 0; i < MAX_FILES; i++) {
        if (!d2->files[i].ino)
            map[d2->files[i].ino]++;
    }

    if (name[(pos-name)+1] == '&') {
        for (int i = 1; i < MAX_FILES; i++) {
            if (map[i] != 2) {
                map[i] = 0;
            } else {
                printf("%s\n", filemap[i].name);
            }
        }
    } else if (name[(pos-name)+1] == '|') {
        for (int i = 1; i < MAX_FILES; i++) {
            if (map[i] > 0) {
                printf("%s\n", filemap[i].name);
            }
        }
    } else if (name[(pos-name)+1] == '^') {
        for (int i = 1; i < MAX_FILES; i++) {
            if (map[i] != 1) {
                map[i] = 0;
            } else {
                printf("%s\n", filemap[i].name);
            }
        }
    }
    //show ones that repeat &, all |, show up once ^, or in the first but not the second ~
    //use a hash, fill with one dir and compare with the other
    //do refreshdir
    free(dir1);
    free(dir2);
}

static void smt_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
    struct fuse_entry_param e;
    khint_t k;

    memset(&e, 0, sizeof(e));
    char const *pos = strchr(name, '\\');
    if (pos != NULL && (pos-name)+1 != strlen(name)) {
        dirset(name, pos);
    }

    k = add_opendir(parent);

    if (k != kh_end(opendirh)) {
        struct opendirinfo *opendir = kh_val(opendirh, k);
        for (int i = 0; i < MAX_FILES; i++) {
            if (opendir->fileinos[i] && !strncmp(opendir->filenames[i], name, strlen(name))) {
                struct file_info f = filemap[opendir->fileinos[i]];
                e.ino = f.ino;
                e.attr.st_ino = f.ino;
                e.attr.st_mode = f.mode;
                e.attr_timeout = 1.0;
                e.entry_timeout = 1.0;
                e.attr.st_nlink = f.nlink;

                if ((f.mode & S_IFMT) == S_IFDIR) {
                    refreshdir(NULL, NULL, f.ino, 0);
                }
                fuse_reply_entry(req, &e);
                return;
            }
        }
    }
    fuse_reply_err(req, ENOENT);
}

static void smt_forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup) {
    int res = EMLINK;
    printf("nlink: %ld\n", filemap[ino].nlink);
    if (filemap[ino].ino && (filemap[ino].nlink == 0 || ((filemap[ino].mode & S_IFMT) == S_IFDIR && filemap[ino].nlink == 1))) {
        remove_file(ino);
        res = 0;
    }
    fuse_reply_err(req, res);
}

static void smt_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    struct stat stbuf;

    if (frmp.currfree > ino) {
        struct file_info f = filemap[ino];
        stbuf.st_mode = f.mode;
        stbuf.st_nlink = f.nlink;
        stbuf.st_size = f.size;
        fuse_reply_attr(req, &stbuf, 1.0);
        return;
    }

    fuse_reply_err(req,ENOENT);
}

static void smt_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr, int to_set, struct fuse_file_info *fi)
{
    struct stat stbuf;

    if ((filemap[ino].mode & S_IFMT) == S_IFDIR) {
        fuse_reply_err(req, EISDIR);
        return;
    }

    stbuf.st_ino = ino;
    stbuf.st_mode = filemap[ino].mode;
    stbuf.st_nlink = filemap[ino].nlink;
    stbuf.st_size = filemap[ino].size;

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

void smt_opendir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    puts("opendir called");
    fi->fh = ino;
    fi->cache_readdir = 0;
    fi->keep_cache = 0;
    //opendirmap and file handler here!!
    fuse_reply_open(req, fi);
}

static void smt_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    if ((filemap[ino].mode & S_IFMT) == S_IFDIR) {
        fuse_reply_err(req, EISDIR);
    } else {
        //char path[256];
        //sprintf(path, "%s/*/%s", devfile, filemap[ino].name);
        /*int fd = open(path, fi->flags & ~O_NOFOLLOW);
        if (fd == -1)
            return (void) fuse_reply_err(req, errno);
        fi->fh = fd;
        printf("%d\n", fd);*/
        fuse_reply_open(req, fi);
    }
}

static void smt_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode) {

    struct fuse_entry_param e;
    memset(&e, 0, sizeof(e));

    khint_t k = kh_get(dirhash, dirh, name); //make sure the name isn't already present

    if (frmp.currfree < MAX_FILES && k == kh_end(dirh)) {
        ino_t ino = add_file(0x0, 0x0, name, S_IFDIR);

        k = kh_get(opendirhash, opendirh, 1);
        if (k != kh_end(opendirh))
            refreshdir(NULL, NULL, 1, 0);

        if (parent != 1) {
            add_filetodir(filemap[parent].name, ino);

            k = kh_get(opendirhash, opendirh, parent);
            if (k != kh_end(opendirh))
                refreshdir(NULL, NULL, parent, 0);
        }

        e.ino = ino;
        e.attr.st_ino = ino;
        e.attr.st_mode = filemap[ino].mode;
        e.attr.st_nlink = filemap[ino].nlink;
        e.attr.st_size = filemap[ino].size;

        fuse_reply_entry(req, &e);
        return;
    }

    fuse_reply_err(req, ENOSPC);
}

static void smt_rename(fuse_req_t req, fuse_ino_t parent, const char *name, fuse_ino_t newparent, const char *newname, unsigned int flags)
{
	int res = ENOENT;

	if (flags) {
		fuse_reply_err(req, EINVAL);
		return;
	}

    khint_t k;
    k = add_opendir(parent);

    if (k != kh_end(opendirh)) {
        struct opendirinfo *opendir = kh_val(opendirh, k);
        for (int i = 0; i < MAX_FILES; i++) {
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
                    struct dirinfo *newdir = add_directory(olddir->ino, f->name, olddir->dironly);
                    newdir->files = olddir->files;
                    remove_directory(name);
                }

                strncpy(opendir->filenames[i], newname, strlen(newname));
                opendir->filenames[i][strlen(newname)] = 0x0;

                if (parent != newparent) {
                    add_filetodir(filemap[newparent].name, f->ino);

                    k = kh_get(opendirhash, opendirh, newparent);
                    if (k != kh_end(opendirh))
                        refreshdir(NULL, NULL, newparent, 0);
                }

                res = 0;
                break;
            }
        }
    }

	fuse_reply_err(req, res);
}

static void smt_create(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode, struct fuse_file_info *fi)
{
    struct fuse_entry_param e;
    memset(&e, 0, sizeof(e));

    printf("create called with filename %s and mode %d\n", name, mode);

    struct dirinfo *dir;
    khint_t k;
    k = kh_get(dirhash, dirh, filemap[parent].name);
    if (k != kh_end(dirh)) {
        dir = kh_val(dirh, k);
    }

    if (frmp.currfree < MAX_FILES && !(((mode & S_IFMT) != S_IFDIR) && dir->dironly)) {
        ino_t ino = add_file(strlen("dummy")+1, strdup("dummy"), name, mode);

        k = kh_get(opendirhash, opendirh, 2);
        if (k != kh_end(opendirh))
            refreshdir(NULL, NULL, 2, 0);

        if (parent != 2) {
            add_filetodir(filemap[parent].name, ino);
            k = kh_get(opendirhash, opendirh, parent);
            if (k != kh_end(opendirh))
                refreshdir(NULL, NULL, parent, 0);
        }

        e.ino = ino;
        e.attr.st_ino = ino;
        e.attr.st_mode = filemap[ino].mode;
        e.attr.st_nlink = filemap[ino].nlink;
        e.attr.st_size = filemap[ino].size;

        fuse_reply_create(req, &e, fi);
        return;
    }

    fuse_reply_err(req, EPERM);
}

static void smt_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi)
{
    (void) fi;

    if ((filemap[ino].mode & S_IFMT) == S_IFDIR) {
        fuse_reply_err(req, EISDIR);
    } else if (ino < frmp.currfree) {
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
        for (int i = 0; i < MAX_FILES; i++) {
            if (opendir->fileinos[i] && !strncmp(opendir->filenames[i], name, strlen(name))) {
                struct file_info f = filemap[opendir->fileinos[i]];
                remove_filefromdir(filemap[parent].name, f.ino);

                k = kh_get(opendirhash, opendirh, parent);
                if (k != kh_end(opendirh))
                    refreshdir(NULL, NULL, parent, 0);

                if (parent == 2) { //if unlinking from *, unlink from everywhere and free file
                    remove_file(f.ino);

                    k = kh_get(opendirhash, opendirh, 2);
                    if (k != kh_end(opendirh))
                        refreshdir(NULL, NULL, 2, 0);
                }
                res = 0;
                break;
            }
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
        if (dir->ino != 1 && dir->ino != 2 && filemap[dir->ino].nlink > 0) {
            remove_filefromdir(filemap[parent].name, dir->ino);

            k = kh_get(opendirhash, opendirh, parent);
            if (k != kh_end(opendirh)) {
                refreshdir(NULL, NULL, parent, 0);
            }

            if (parent == 1) { //if unlinking from /, unlink everywhere. The fs will call forget() next
                struct file_info f = filemap[dir->ino];
                for (int j = 0; j < MAX_DIR; j++) {
                    if (f.dir[j]) {
                        remove_filefromdir(filemap[f.dir[j]].name, f.ino);

                        k = kh_get(opendirhash, opendirh, f.dir[j]);
                        if (k != kh_end(opendirh)) {
                            refreshdir(NULL, NULL, f.dir[j], 0);
                        }
                    }
                }
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
        filemap[ino].size = off + size;
        memcpy(filemap[ino].data + off, buf, size);
        fuse_reply_write(req, size);
        return;
    }
}

static void smt_flush(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	//int res;
	//res = close(dup(fi->fh));
	//fuse_reply_err(req, res == -1 ? errno : 0);
	fuse_reply_err(req, 0);
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
        value = malloc(size);
        ret = sizeof(value);
        printf("value %ld %ld\n", sizeof(value), ret);
        char *p = value;
        for (int i = 0; i < MAX_DIR; i++) {
            if (f.dir[i]) {
                printf("%ld\n", f.dir[i]);
                printf("%s\n", filemap[f.dir[i]].name);
                p = memccpy(p, filemap[f.dir[i]].name, '\0', strlen(filemap[f.dir[i]].name)+1);
            }
        }
		fuse_reply_buf(req, value, ret);
    } else {
        for (int i = 0; i < MAX_DIR; i++) {
            if (f.dir[i]) {
                ret += strlen(filemap[f.dir[i]].name)+1;
            }
        }
        ret += 8 - (ret%8);
        printf("ret %ld\n", ret);
		fuse_reply_xattr(req, ret);
    }
    free(value);
}

int recursive_dir(ino_t dirino, ino_t ino) {
    if (dirino == ino) {
        return EPERM;
    }

    int saverr = 0;
    for (int i = 0; i < MAX_DIR; i++) {
        if (filemap[dirino].dir[i]) {
            saverr = recursive_dir(filemap[dirino].dir[i], ino);
            if (saverr) {
                return saverr;
            }
        }
    }

    return saverr;
}

static void smt_setxattr(fuse_req_t req, fuse_ino_t ino, const char *name, const char *value, size_t size, int flags)
{
    int saverr = EPERM;
    //don't allow tagging the universal directories / and *
    if (ino < 3) {
        fuse_reply_err(req, saverr);
        return;
    }

    khint_t k;
    k = kh_get(dirhash, dirh, name);

    if (k != kh_end(dirh)) {
        struct dirinfo *dir = kh_value(dirh, k);
        for (int i = 0; i < MAX_DIR; i++) { //check if dir being added is already present
            if (filemap[ino].dir[i] == dir->ino) {
                fuse_reply_err(req, saverr);
                return;
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
        k = kh_get(opendirhash, opendirh, dir->ino);
        if (k != kh_end(opendirh))
            refreshdir(NULL, NULL, dir->ino, 0);
    } else {
        add_file(0x0, 0x0, name, S_IFDIR);
        saverr = add_filetodir(name, ino);
    }

    fuse_reply_err(req, saverr);
}

static void smt_removexattr(fuse_req_t req, fuse_ino_t ino, const char *name) {
    int saverr = EPERM;
    khint_t k;
    //don't allow removing the universals tags / and *
    if (ino < 3) {
        fuse_reply_err(req, saverr);
        return;
    }

    k = kh_get(dirhash, dirh, name);
    if (k != kh_end(dirh)) {
        struct dirinfo *dir = kh_value(dirh, k);
        for (int i = 0; i < MAX_DIR; i++) {
            if (filemap[ino].dir[i] == dir->ino) {
                saverr = 0;
                break;
            }
        }
        remove_filefromdir(name, ino);

        k = kh_get(opendirhash, opendirh, dir->ino);
        if (k != kh_end(opendirh)) {
            refreshdir(NULL, NULL, dir->ino, 0);
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
    .opendir = smt_opendir,
    .open = smt_open,
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
    fuse_opt_free_args(&args);
    return retval;
}


