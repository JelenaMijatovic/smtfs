#define FUSE_USE_VERSION FUSE_MAKE_VERSION(3, 17)

#define MAX_FILES 10
#define MAX_DIR 10
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
    ino_t *dir; //set of strings
};

struct file_map {
    int ffree;
    struct file_info files[MAX_FILES*10];
};

struct file_map fm;

struct dirinfo {
    ino_t ino;
    bool dironly;
    int ffree;
    ino_t *files; //set of inodes
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
        dir->ffree = 0;
        dir->files = malloc(MAX_FILES*sizeof(ino_t));
        k = kh_put(dirhash, dirh, fm.files[ino].name, &absent);
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

    k = kh_get(dirhash, dirh, name);
    if (k != kh_end(dirh)) {
        dir = kh_val(dirh, k);
        if (dir->ffree < MAX_FILES) {
            dir->files[dir->ffree] = ino;
            fm.files[ino].dir[fm.files[ino].ffree] = dir->ino;
            fm.files[ino].ffree++;
            fm.files[ino].nlink++;
            printf("adding file %ld at %d\n", dir->files[dir->ffree], dir->ffree);
            return dir->ffree++;
        }
    }

    return 0;
}

int add_file(size_t size, char *data, const char *name, mode_t mode) {

    if (fm.ffree < MAX_FILES*10) {
        fm.files[fm.ffree].ino = fm.ffree;
        fm.files[fm.ffree].name = (char *)malloc(MAX_FILENAME_LEN);
        strncpy(fm.files[fm.ffree].name, name, strlen(name));
        fm.files[fm.ffree].name[strlen(name)] = 0x0;
        fm.files[fm.ffree].size = size;
        fm.files[fm.ffree].data = data;
        fm.files[fm.ffree].mode = mode | 0777;
        fm.files[fm.ffree].fd = 0;
        fm.files[fm.ffree].ffree = 0;
        fm.files[fm.ffree].dir = malloc(MAX_DIR*sizeof(ino_t));
        if ((mode & S_IFMT) == S_IFDIR) {
            fm.files[fm.ffree].nlink = 1;
            add_directory(fm.ffree, name, 0);
            add_filetodir(fm.files[1].name, fm.ffree); //root directory contains all directories (bar itself)
        } else {
            fm.files[fm.ffree].nlink = 0;
            add_filetodir(fm.files[2].name, fm.ffree); //* directory contains all regular files
        }
        return fm.ffree++;
    }
    return -1;
}

struct opendirinfo {
    ino_t ino;
    char filenames[MAX_FILES][MAX_FILENAME_LEN]; //filename-inode hashmap
    ino_t fileinos[MAX_FILES];
};

KHASH_MAP_INIT_INT(opendirhash, struct opendirinfo*)
khash_t(opendirhash) *opendirh; //cache method

khint_t add_opendir(ino_t ino) {

    khint_t k;
    int absent;

    k = kh_get(opendirhash, opendirh, ino);
    if (k == kh_end(opendirh)) {
        struct opendirinfo *dir = malloc(sizeof(struct opendirinfo*));
        dir->ino = ino;
        k = kh_put(opendirhash, opendirh, ino, &absent);
        kh_val(opendirh, k) = dir;
    }

    return k;
}

void fatal_error(const char *message) {
    puts(message);
    exit(1);
}

static void smt_init(void *userdata, struct fuse_conn_info *conn) {

    fm.ffree = 1; //init to inode 1
    dirh = kh_init(dirhash);
    opendirh = kh_init(opendirhash);

    add_file(0x0, 0x0, strdup("/"), S_IFDIR);

    //root directory shouldn't contain itself
    fm.files[1].dir[0] = 0;
    fm.files[1].ffree = 0;
    khint_t k = kh_get(dirhash, dirh, fm.files[1].name);
    if (k != kh_end(dirh)) {
        struct dirinfo *dir = kh_val(dirh, k);
        dir->files[0] = 0;
        dir->ffree = 0;
    } else {
        fatal_error("Couldn't find root directory in hash");
    }

    add_file(0, 0x0, strdup("*"), S_IFDIR);
}

static void smt_destroy(void *userdata) {
    for (khint_t k = 0; k < kh_end(opendirh); ++k)
        if (kh_exist(opendirh, k)) {
            free(kh_val(opendirh, k));
        }
    kh_destroy(opendirhash, opendirh);

    for (khint_t k = 0; k < kh_end(dirh); ++k)
        if (kh_exist(dirh, k)) {
            struct dirinfo* dir = kh_val(dirh, k);
            printf("%ld\n", dir->ino);
            free(dir->files);
            free(dir);
            //free((char*)kh_key(dirh, k));
        }
    kh_destroy(dirhash, dirh);

    for (int i = 1; i < fm.ffree; i++) {
        free(fm.files[i].name);
        free(fm.files[i].data);
        free(fm.files[i].dir);
    }

    printf("finished cleanup\n");
}

static void smt_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
    struct fuse_entry_param e;
    khint_t k;

    memset(&e, 0, sizeof(e));
    char const *pos = strstr(name, "\\"); //and maybe multiples
    if (pos != NULL && (pos-name)+1 != strlen(name)) {
        if (name[(pos-name)+1] == '&') {

            char *dir1 = (char *)malloc((pos-name)+1);
            strncpy(dir1, name, pos-name);
            dir1[pos-name] = '\0';
            char *dir2 = (char *)malloc(strlen(name)-(pos-name));
            strncpy(dir2, name+(pos-name)+2, strlen(name)-(pos-name)-1);
            dir2[strlen(name)-(pos-name)-1] = '\0';

            struct dirinfo *d1;
            k = kh_get(dirhash, dirh, dir1);
            if (k != kh_end(dirh)) {
                d1 = kh_val(dirh, k);
                printf("found %ld\n", d1->ino);
            }
            struct dirinfo *d2;
            k = kh_get(dirhash, dirh, dir2);
            if (k != kh_end(dirh)) {
                d2 = kh_val(dirh, k);
                printf("found %ld\n", d2->ino);
            }

            //open both directories, compare file inodes
            //show ones that repeat &, all |, show up once ^, or in the first but not the second ~
            //use a hash, fill with one dir and compare with the other
            //do ropendir
            free(dir1);
            free(dir2);
        }
    }

    k = add_opendir(parent);

    if (k != kh_end(opendirh)) {
        struct opendirinfo *opendir = kh_val(opendirh, k);
        for (int i = 0; i < MAX_FILES; i++) {
            if (!strncmp(opendir->filenames[i], name, strlen(name))) {
                struct file_info f = fm.files[opendir->fileinos[i]];
                e.ino = f.ino;
                e.attr.st_ino = f.ino;
                e.attr.st_mode = f.mode;
                e.attr_timeout = 1.0;
                e.entry_timeout = 1.0;
                e.attr.st_nlink = f.nlink;
                fuse_reply_entry(req, &e);
                return;
            }
        }
    }
    fuse_reply_err(req, ENOENT);
}

static void smt_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    struct stat stbuf;

    if (fm.ffree > ino) {
        struct file_info f = fm.files[ino];
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

    if ((fm.files[ino].mode & S_IFMT) == S_IFDIR) {
        fuse_reply_err(req, EISDIR);
        return;
    }

    stbuf.st_ino = ino;
    stbuf.st_mode = fm.files[ino].mode;
    stbuf.st_nlink = fm.files[ino].nlink;
    stbuf.st_size = fm.files[ino].size;

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

struct dirbuf {
	char *p;
	size_t size;
};

static void dirbuf_add(fuse_req_t req, struct dirbuf *b, const char *name, fuse_ino_t ino)
{
    printf("test in dirbufadd\n");
	struct stat stbuf;
	size_t oldsize = b->size;

	printf("%ld %s\n", b->size, name);
	b->size += fuse_add_direntry(req, NULL, 0, name, NULL, 0);
	b->p = (char *) realloc(b->p, b->size);
	memset(&stbuf, 0, sizeof(stbuf));
	stbuf.st_ino = ino;
	fuse_add_direntry(req, b->p + oldsize, b->size - oldsize, name, &stbuf, b->size);
	printf("exit dirbufadd\n");
}

void ropendir(fuse_req_t req, struct dirbuf *b, ino_t ino, int addbuff) {

    printf("ropendir in directory -> %ld\n", ino);

    struct dirinfo *dir = NULL;
    khint_t k;
    k = kh_get(dirhash, dirh, fm.files[ino].name);
    if (k != kh_end(dirh)) {
        dir = kh_val(dirh, k);
        printf("found directory -> %ld\n", ino);
    }

    k = add_opendir(ino);

    if (k != kh_end(opendirh) && dir != NULL) {
        struct opendirinfo *opendir = kh_val(opendirh, k);
        for (int i = 0; i < dir->ffree; i++) {
            struct file_info f = fm.files[dir->files[i]];
            printf("found file -> %ld at %d\n", dir->files[i], i);
            char* name;
            char app[3] = {'~', '0', '\0'};
                if ((name = malloc(strlen(f.name)+strlen(app)+1)) != NULL){
                    for (int j = 0; j < i; j++) {
                        int k = 1;
                        if (!strcmp(opendir->filenames[j], name)) {
                            name[0] = '\0';
                            app[1] = k + '0';
                            strcat(name,f.name);
                            strcat(name, app);
                            k++;
                        }
                    }
                    if (app[1] != '0') {
                        strcpy(opendir->filenames[i], name);
                    } else {
                        strcpy(opendir->filenames[i], f.name);
                    }
                    free(name);
                } else {
                    strcpy(opendir->filenames[i], f.name);
                }
                opendir->fileinos[i] = f.ino;
                printf("Adding entry for filename -> %s | inode -> %ld\n", f.name, f.ino);
                if (addbuff) {
                    dirbuf_add(req, b, f.name, f.ino);
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

void smt_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
                     struct fuse_file_info *fi)
{
    (void)fi;
    struct dirbuf b;

    memset(&b, 0, sizeof(b));

    dirbuf_add(req, &b, ".", ino);
    dirbuf_add(req, &b, "..", ino);
    ropendir(req, &b, ino, 1);

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
    if ((fm.files[ino].mode & S_IFMT) == S_IFDIR) {
        fuse_reply_err(req, EISDIR);
    } else {
        //char path[256];
        //sprintf(path, "%s/*/%s", devfile, fm.files[ino].name);
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

    if (fm.ffree < MAX_FILES) {
        ino_t ino = add_file(0x0, 0x0, name, S_IFDIR);
        ropendir(NULL, NULL, 1, 0);
        if (parent != 1) {
            add_filetodir(fm.files[parent].name, ino);
            ropendir(NULL, NULL, parent, 0);
        }

        e.ino = ino;
        e.attr.st_ino = ino;
        e.attr.st_mode = fm.files[ino].mode;
        e.attr.st_nlink = fm.files[ino].nlink;
        e.attr.st_size = fm.files[ino].size;

        fuse_reply_entry(req, &e);
        return;
    }

    fuse_reply_err(req, ENOSPC);
}

static void smt_rename(fuse_req_t req, fuse_ino_t parent, const char *name, fuse_ino_t newparent, const char *newname, unsigned int flags)
{
	int res = -1;

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
                struct file_info *f = &fm.files[opendir->fileinos[i]];
                strncpy(f->name, newname, strlen(newname));
                f->name[strlen(newname)] = 0x0;
                strncpy(opendir->filenames[i], newname, strlen(newname));
                opendir->filenames[i][strlen(newname)] = 0x0;
                res = 0; //<- check here and refresh open dir ^
                break;
            }
        }
    }

	fuse_reply_err(req, res == -1 ? errno : 0);
}

static void smt_create(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode, struct fuse_file_info *fi)
{
    struct fuse_entry_param e;
    memset(&e, 0, sizeof(e));

    printf("create called with filename %s and mode %d\n", name, mode);

    struct dirinfo *dir;
    khint_t k;
    k = kh_get(dirhash, dirh, fm.files[parent].name);
    if (k != kh_end(dirh)) {
        dir = kh_val(dirh, k);
    }

    if (fm.ffree < MAX_FILES && !(((mode & S_IFMT) != S_IFDIR) && dir->dironly)) {
        ino_t ino = add_file(strlen("dummy"), strdup("dummy"), name, mode);
        ropendir(NULL, NULL, 2, 0);
        if (parent != 2) {
            add_filetodir(fm.files[parent].name, ino);
            ropendir(NULL, NULL, parent, 0);
        }

        e.ino = ino;
        e.attr.st_ino = ino;
        e.attr.st_mode = fm.files[ino].mode;
        e.attr.st_nlink = fm.files[ino].nlink;
        e.attr.st_size = fm.files[ino].size;

        fuse_reply_create(req, &e, fi);
        return;
    }

    fuse_reply_err(req, ENOSPC);
}

static void smt_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi)
{
    (void) fi;

    if ((fm.files[ino].mode & S_IFMT) == S_IFDIR) {
        fuse_reply_err(req, EISDIR);
    } else if (ino < fm.ffree) {
        reply_buf_limited(req, fm.files[ino].data, fm.files[ino].size, off, size);
        return;
    }
    fuse_reply_err(req, ENOENT);
}

static void smt_unlink(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	int res = -1;
    khint_t k;

    k = add_opendir(parent);

    if (k != kh_end(opendirh)) {
        struct opendirinfo *opendir = kh_val(opendirh, k);
        for (int i = 0; i < MAX_FILES; i++) {
            if (!strncmp(opendir->filenames[i], name, strlen(name))) {
                struct file_info f = fm.files[opendir->fileinos[i]];
                for (int j = 0; j < MAX_DIR; j++) {
                    //remove inode from every f.dir[i];
                }
                free(f.name);
                free(f.data);
                ropendir(NULL, NULL, parent, 0);
                res = 0;
            }
        }
    }

	fuse_reply_err(req, res == -1 ? errno : 0);
}

static void smt_write(fuse_req_t req, fuse_ino_t ino, const char *buf, size_t size, off_t off, struct fuse_file_info *fi)
{
    printf("write called on the file %ld\n", ino);
    printf("offset = %lu and size=%zu\n", off, size);
    if ((fm.files[ino].mode & S_IFMT) == S_IFDIR) {
        fuse_reply_err(req, EISDIR);
    } else if (ino < fm.ffree) {
        if (fm.files[ino].size == 0) {
            fm.files[ino].data = malloc(size + off);
        } else {
            fm.files[ino].data = realloc(fm.files[ino].data, off + size);
        }
        fm.files[ino].size = off + size;
        memcpy(fm.files[ino].data + off, buf, size);
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

	res = fstatvfs(fm.files[ino].fd, &stbuf);
	if (res == -1)
		fuse_reply_err(req, errno);
	else
		fuse_reply_statfs(req, &stbuf);
}*/

static void smt_listxattr(fuse_req_t req, fuse_ino_t ino, size_t size)
{
	char *value = NULL;
    ssize_t ret = 0;
    struct file_info f = fm.files[ino];

    if (size) {
        value = malloc(size);
        for (int i = 0; i < f.ffree; i++) {
            printf("%s %ld\n", fm.files[f.dir[i]].name, size);
            //strcat
            strncpy(value, fm.files[f.dir[i]].name, strlen(fm.files[f.dir[i]].name));
            printf("value %ld\n", sizeof(value));
            value[strlen(fm.files[f.dir[i]].name)] = 0x0;
        }
		fuse_reply_buf(req, value, ret);
    } else {
        for (int i = 0; i < f.ffree; i++) {
            ret += sizeof(fm.files[f.dir[i]].name);
        }
        printf("ret %ld\n", ret);
		fuse_reply_xattr(req, ret);
    }
    free(value);
}

static void smt_setxattr(fuse_req_t req, fuse_ino_t ino, const char *name, const char *value, size_t size, int flags)
{
    int saverr = ENOSYS;
    khint_t k;
    k = kh_get(dirhash, dirh, name);

    if (k != kh_end(dirh)) { //check if already there
        add_filetodir(name, ino);
    } else {
        add_file(0x0, 0x0, name, S_IFDIR);
        add_filetodir(name, ino);
    }

    saverr = 0;

    fuse_reply_err(req, saverr);
}

static struct fuse_lowlevel_ops operations = {
    .init = smt_init,
    .destroy = smt_destroy,
    .lookup = smt_lookup,
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
    .write = smt_write,
    .flush = smt_flush,
    .release = smt_release,
    .listxattr = smt_listxattr,
    .setxattr = smt_setxattr,
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


