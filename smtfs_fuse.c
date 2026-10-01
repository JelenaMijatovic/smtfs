#include "smtfs.h"
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/sysmacros.h>

//filename hashmap used in refreshdir to check for duplicates
KHASH_MAP_INIT_STR(filenamehash, struct freeino*)

//directory entry buffer for smt_readdir
struct dirbuf {
	char *p;
	off_t size;
};

struct smtfs_config config;
pthread_t refresh_thread;
static void smt_destroy(void *userdata);
int recursive_dir(ino_t dirino, ino_t ino);

void fatal_error(const char *message) {
    puts(message);
    smt_destroy(NULL);
    exit(1);
}

//run on first mount
void smtfs_setup() {

    //initialise values
    freemap = malloc(sizeof(struct freeino));
    freemap->ino = 1; //start inodes from 1
    freemap->nextfr = NULL;
    config.used = 0;

    //create system directories
    char *root = strdup("/");
    add_sysdirs(root, S_IFDIR | 0777);
    add_opendir(ROOT); //load root into cache immediately

    char *tags = strdup(TAGS_FN);
    add_sysdirs(tags, S_IFDIR | 0777);
    add_filetodir(root, TAGS);
    free(tags);

    char *files = strdup(FILES_FN);
    add_sysdirs(files, S_IFDIR | 0777);
    add_filetodir(root, FILES);
    free(files);

    char *home = strdup(HOME_FN);
    add_sysdirs(home, S_IFDIR | 0777);
    add_filetodir(root, HOME);
    free(home);

    free(root);
}

//run on subsequent mounts
void smtfs_load() {
    khint_t k;
    int absent;

    //check if error directory is present
    char* path = get_file_path(config.storage, "/ERR");
    if (path) {
        //!repair errors <- separate option
        //remove(path);
        free(path);
    }

    //load data into freemap
    path = get_file_path(config.storage, "/free.txt");
    if (path) {
        FILE *fptr;
        fptr = fopen(path, "r");
        if (fptr) {
            ino_t ino;
            struct freeino *prev = malloc(sizeof(struct freeino));

            fscanf(fptr, "%lu\n", &config.used);
            //at least one free inode (the first) is always present
            fscanf(fptr, "%lu\n", &prev->ino);
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

    //load data into dirhash
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
                            add_directory(entry->d_name, ino);
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
                } else {
                    ino = freemap->ino++;
                }
                add_directory(importname, ino);
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
            printf("import_dir: Couldn't open import directory, import aborted.\n");
        }
    } else {
        printf("import_dir: Import path isn't directory, import aborted.\n");
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

                printf("Importing directory %s...\n", importdir);
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
                                add_directory(entry->d_name, ino);
                                open_file(ino, entry->d_name, 0777 | S_IFDIR);

                                append_dir_contents(TAGS, ino);
                                set_file_xattr(ino, TAGS_FN, ADD);

                                append_dir_contents(parent, ino);
                                set_file_xattr(ino, parentname, ADD);
                            } else {
                                struct dirinfo *dir = kh_val(dirh, k);
                                ino = dir->ino;

                                //check if it's been added to a new directory
                                int size = listxattr(entrpath, 0, 0);
                                if (size > 0) {
                                    char* list = malloc(size);
                                    if (list) {
                                        listxattr(entrpath, list, size);
                                        int sum = 0;
                                        char *s = list;
                                        char *p;
                                        while (sum < size) {
                                            p = strstr(s, "user.smtfs.");
                                            if (p) {
                                                p = p + strlen("user.smtfs.");
                                                khint_t k = kh_get(dirhash, dirh, p);
                                                if (k != kh_end(dirh)) {
                                                    struct dirinfo *dir = kh_val(dirh, k);
                                                    if (dir->ino == parent) {
                                                        break;
                                                    }
                                                }
                                            }
                                            sum += strlen(s)+1;
                                            s = strchr(s, '\0');
                                            s++;
                                        }
                                        if (sum >= size) {
                                            append_dir_contents(parent, ino);
                                            set_file_xattr(ino, parentname, ADD);
                                        }
                                    }
                                    free(list);
                                }
                            }

                            refresh_importdir(entrpath, ino, entry->d_name);

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
                                    memset(&stbuf, 0, sizeof(stbuf));

                                    int res = stat(stpath, &stbuf);
                                    if (res && errno == ENOENT) {
                                        unlink(stpath);
                                        create_symlink(ino, entry->d_name, entrpath);

                                        free(stpath);
                                        stpath = entrpath;
                                    }

                                    int size = listxattr(entrpath, 0, 0);
                                    if (size > 0) {
                                        char* list = malloc(size);
                                        if (list) {
                                            listxattr(entrpath, list, size);
                                            int sum = 0;
                                            char *s = list;
                                            char *p;
                                            while (sum < size) {
                                                p = strstr(s, "user.smtfs.");
                                                if (p) {
                                                    p = p + strlen("user.smtfs.");
                                                    khint_t k = kh_get(dirhash, dirh, p);
                                                    if (k != kh_end(dirh)) {
                                                        struct dirinfo *dir = kh_val(dirh, k);
                                                        if (dir->ino == parent) {
                                                            break;
                                                        }
                                                    }
                                                }
                                                sum += strlen(s)+1;
                                                s = strchr(s, '\0');
                                                s++;
                                            }
                                            if (sum >= size) {
                                                append_dir_contents(parent, ino);
                                                set_file_xattr(ino, parentname, ADD);
                                            }
                                        }
                                        free(list);
                                    }
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
            char *name = malloc(PATH_MAX);
            if (importdir) {
                while (fgets(importdir, PATH_MAX, fptr) != NULL) {
                    char *p = strchr(importdir, '\n');
                    *p = '\0';
                    strcpy(name, basename(importdir));
                    khint_t k = kh_get(dirhash, dirh, name);
                    if (k != kh_end(dirh)) {
                        struct dirinfo *dir = kh_val(dirh, k);

                        printf("Refreshing import dir %s...\n", importdir);

                        refresh_importdir(importdir, dir->ino, name);
                    } else {
                        printf("refresh_imports: Couldn't find import directory %s in smtfs\n", name);
                    }

                    memset(importdir, 0, PATH_MAX);
                    memset(name, 0, PATH_MAX);
                }
                free(importdir);
                free(name);
            } else {
                fatal_error("refresh_imports: Couldn't allocate memory");
            }
            fclose(fptr);
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
    printf("Done.\n");
}

static void smt_init(void *userdata, struct fuse_conn_info *conn) {

    dirh = kh_init(dirhash);
    fcache = kh_init(openfilehash);
    opendirh = kh_init(opendirhash);
    lvisit.currindex = 0;
    lvisit.visits = calloc(MAX_OPEN, sizeof(struct vst));
    if (!lvisit.visits) {
        fatal_error("Couldn't allocate last_visited!");
    }

    //load relevant runtime configuration
    struct fuse_smt_userdata *fuseconf = userdata;
    config.passthrough = fuseconf->passthrough;
    config.root_fd = fuseconf->root_fd;
    config.devfile = fuseconf->devfile;
    config.storage = fuseconf->storage;
    config.backup = fuseconf->backup;
    config.dev = fuseconf->dev;
    config.blksize = fuseconf->blksize;
    config.errcount = 0;
    config.errpath = get_file_path(config.storage, "/ERR");

    //test if storage is set up
    DIR *test_fd = NULL;
    char *path = get_file_path(config.storage, "/0");
    if (path) {
        test_fd = opendir(path);
        free(path);
    }

    if (test_fd) {
        smtfs_load();
        refresh_imports();
    } else {
        smtfs_setup();
    }
    closedir(test_fd);

    if (fuseconf->import) {
        char *importdir = fuseconf->import;
        if (strchr(fuseconf->import, '&')) {
            char *q = importdir;
            while ((q = strchr(q, '&'))) {
                *q = '\0';
                char *fullpath = realpath(importdir, NULL);
                if (fullpath) {
                    add_import(fullpath);
                    free(fullpath);
                }
                *q = '&';
                importdir = ++q;
            }
        }
        char *fullpath = realpath(importdir, NULL);
        if (fullpath) {
            add_import(fullpath);
            free(fullpath);
        }
    }

    add_opendir(ROOT);
    refreshdir(ROOT);

    pthread_create(&refresh_thread, NULL, refresh_cache, NULL);
}

//runs on unmount, saves metadata to disk, clears memory and creates backup
static void smt_destroy(void *userdata) {

    printf("Shutting down...\n");

    pthread_detach(refresh_thread);
    pthread_cancel(refresh_thread);

    //save and clear directory cache
    for (khint_t k = 0; k < kh_end(opendirh); ++k)
        if (kh_exist(opendirh, k)) {
            remove_opendir(kh_key(opendirh, k), STOP);
        }
    kh_destroy(opendirhash, opendirh);

    free(lvisit.visits);

    //save directory inodes into dirs.txt
    write_dirinos_into_file(config.storage, "/dirs.txt");

    //clear dirhash
    for (khint_t k = 0; k < kh_end(dirh); ++k)
        if (kh_exist(dirh, k)) {
            struct dirinfo* dir = kh_val(dirh, k);
            free(dir->name);
            free(dir);
        }
    kh_destroy(dirhash, dirh);

    //save and clear file cache
    for (khint_t k = 0; k < kh_end(fcache); ++k)
        if (kh_exist(fcache, k)) {
            remove_openfile(kh_key(fcache, k), STOP);
        }
    kh_destroy(openfilehash, fcache);

    //save freemap
    write_freemap_into_file(config.storage, "/free.txt");

    //clear freemap
    struct freeino *curr = freemap;
    struct freeino *temp;
    while (curr) {
        temp = curr;
        curr = curr->nextfr;
        free(temp);
    }

    //if error count is zero, create backup
    if (!config.errcount) {
        create_backup(config.backup);
    }

    free(config.errpath);

    printf("Finished cleanup.\n");
}

static void smt_access(fuse_req_t req, fuse_ino_t ino, int mask) {
    //struct stat stbuf;

        //stat(filepath, &stbuf);
        //stbuf.st_mode

    fuse_reply_err(req, ENOSYS);
}

void refreshdir(ino_t ino) {

    struct openfileinfo *f = NULL;
    struct dirinfo *dir = NULL;
    khint_t k, kd;

    k = add_opendir(ino);

    kd = kh_get(openfilehash, fcache, ino);
    if (kd != kh_end(fcache)) {
        f = kh_val(fcache, kd);

        kd = kh_get(dirhash, dirh, f->name);
        if (kd != kh_end(dirh)) {
            dir = kh_val(dirh, kd);
        }
    }

    if (k != kh_end(opendirh) && dir != NULL) {
        khash_t(filenamehash) *fnh = kh_init(filenamehash);
        khint_t k1;
        int absent;

        struct opendirinfo *opendir = kh_val(opendirh, k);
        time(&lvisit.visits[opendir->index].visit);

        //clear old filenames
        for (int i = 0; i < opendir->filenames->size; i++) {
            free(opendir->filenames->entries[i].name);
        }
        free(opendir->filenames->entries);
        opendir->filenames->entries = malloc(sizeof(struct opendirentry)*2);
        memset(opendir->filenames->entries, 0x0, sizeof(struct opendirentry)*2);
        opendir->filenames->size = 0;
        opendir->filenames->exp = 2;

        //load filenames into filenamehash to look for duplicates
        for (int i = 0; i < opendir->fileinos->size; i++) {
            char *name = NULL;

            k = kh_get(openfilehash, fcache, opendir->fileinos->inos[i]);
            if (k != kh_end(fcache)) {
                struct openfileinfo *f = kh_value(fcache, k);
                name = strdup(f->name);
            } else {
                name = (char *)get_xattr_from_file(opendir->fileinos->inos[i], "user.smtfs_m.name");
            }

            if (name) {
                k1 = kh_get(filenamehash, fnh, name);
                if (k1 != kh_end(fnh)) {
                    struct freeino *node = malloc(sizeof(struct freeino));
                    node->ino = opendir->fileinos->inos[i];
                    node->nextfr = NULL;
                    struct freeino *prev = kh_value(fnh, k1);
                    prev->nextfr = node;
                    free(name);
                } else {
                    k1 = kh_put(filenamehash, fnh, name, &absent);
                    struct freeino *node = malloc(sizeof(struct freeino));
                    node->ino = opendir->fileinos->inos[i];
                    node->nextfr = NULL;
                    kh_value(fnh, k1) = node;
                    kh_key(fnh, k1) = name;
                }

            } else {
                printf("refreshdir: failed to load filename for inode %ld\n", opendir->fileinos->inos[i]);
            }
        }

        //generate new filenames
        for (k = 0; k < kh_end(fnh); ++k) {
            if (kh_exist(fnh, k)) {
                struct freeino *node = kh_value(fnh, k);
                char *name = (char*)kh_key(fnh, k);

                if (node->nextfr) {
                    struct freeino *prev = NULL;
                    while (node) {
                        char *newname;
                        int length = snprintf(NULL, 0, "%ld", node->ino);
                        char app[length+1];
                        if ((newname = malloc(strlen(name) + length + 2)) != NULL) {
                            newname[0] = '\0';
                            sprintf(app, "%ld", node->ino);
                            strcat(newname, name);
                            strcat(newname, ":");
                            strcat(newname, app);

                            insert_fname(opendir->filenames, newname, node->ino);

                        } else {
                            printf("refreshdir: filename malloc fail for inode %ld\n", node->ino);
                            continue;
                        }

                        prev = node;
                        node = node->nextfr;
                        free(prev);
                    }
                    free(name);
                } else {
                    insert_fname(opendir->filenames, name, node->ino);

                    free(node);
                }
            }
        }

        kh_destroy(filenamehash, fnh);
    }
}

static void smt_lookup(fuse_req_t req, fuse_ino_t parent, const char *name) {
    struct fuse_entry_param e;
    memset(&e, 0, sizeof(e));
    struct openfileinfo *f = NULL;
    khint_t k;

    k = add_opendir(parent);
    if (k != kh_end(opendirh)) {
        struct opendirinfo *opendir = kh_val(opendirh, k);
        time(&lvisit.visits[opendir->index].visit);

        int pos = find_fname_pos(opendir->filenames, (char *)name);
        if (opendir->filenames->entries[pos].name && !strcmp(opendir->filenames->entries[pos].name, name)) {
            k = add_openfile(opendir->filenames->entries[pos].ino);
            if (k != kh_end(fcache)) {
                f = kh_value(fcache, k);
            }
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
            refreshdir(f->ino); //!called both on cd and ls
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
            int res = remove_file(ino);
            fuse_reply_err(req, res);
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

static void smt_statx(fuse_req_t req, fuse_ino_t ino, int flags, int mask, struct fuse_file_info *fi) {
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

static void smt_opendir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {

    khint_t k = add_opendir(ino);
    if (k != kh_end(opendirh)) {
        struct opendirinfo *opendir = kh_val(opendirh, k);
        time(&lvisit.visits[opendir->index].visit);
        ++opendir->openref;

        fuse_reply_open(req, fi);
    } else {
        fuse_reply_err(req, ENOENT);
    }
}

//add direntry to dirbuf
//return new real size on success, 0 on fail
static off_t dirbuf_add(fuse_req_t req, struct dirbuf *b, off_t realsize, const char *name, fuse_ino_t ino) {
	struct stat stbuf;
	off_t oldsize = realsize;

	//abort if larger than max size
	realsize += fuse_add_direntry(req, NULL, 0, name, NULL, 0);
	if (realsize > b->size) {
        return 0;
	}

	//only ino and mode attributes are used by fuse_add_direntry
	memset(&stbuf, 0, sizeof(stbuf));

	stbuf.st_ino = ino;

	khint_t k = kh_get(openfilehash, fcache, ino);
    if (k != kh_end(fcache)) {
        struct openfileinfo *f = kh_value(fcache, k);
        stbuf.st_mode = f->mode;
    }

    //use current inode as offset
	fuse_add_direntry(req, b->p + oldsize, b->size - oldsize, name, &stbuf, ino);

	return realsize;
}

static void smt_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi) {

    //empty directories will set offset to their own inodes on next call, send empty buffer (end of stream)
    if (ino == off) {
        fuse_reply_buf(req, NULL, 0);
        return;
    }

    khint_t k = add_opendir(ino);
    if (k != kh_end(opendirh)) {
        struct opendirinfo *opendir = kh_val(opendirh, k);

        time(&lvisit.visits[opendir->index].visit);

        //if offset is set, find the index of the last added file in opendir->filenames and continue from there
        int pos;
        if (off) {
            k = add_openfile(off);
            if (k != kh_end(fcache)) {
                struct openfileinfo *f = kh_val(fcache, k);

                //iterate through identical names until the inode set in offset is found
                pos = find_fname_pos(opendir->filenames, f->name);
                while (strncmp(opendir->filenames->entries[pos].name, f->name, strlen(f->name))) {
                    if (opendir->filenames->entries[pos].ino == off) {
                        break;
                    }
                    ++pos;
                }
                //inode not found
                if (opendir->filenames->entries[pos].ino != off) {
                    fuse_reply_err(req, ENOENT);
                    return;
                }
                //if pos is at last index or larger, send empty buffer (end of stream)
                if (pos >= opendir->filenames->size-1) {
                    fuse_reply_buf(req, NULL, 0);
                    return;
                }
                ++pos; //move index to first new file
            } else {
                fuse_reply_err(req, ENOENT);
                return;
            }
        } else {
            pos = 0;
        }

        (void)fi;
        struct dirbuf b;
        off_t realsize = 0;

        //initialise buffer to maxsize
        memset(&b, 0, sizeof(b));
        b.size = size;
        b.p = (char *)malloc(size);

        //only include "." and ".." on first read
        if (!off) {
            realsize = dirbuf_add(req, &b, realsize, ".", ino);
            realsize = dirbuf_add(req, &b, realsize, "..", ino);
        }

        //add direntries to buffer until it's full
        off_t res;
        for (int i = pos; i < opendir->filenames->size; i++) {
            res = dirbuf_add(req, &b, realsize, opendir->filenames->entries[i].name, opendir->filenames->entries[i].ino);
            if (res) {
                realsize = res;
            } else {
                break;
            }
        }

        fuse_reply_buf(req, b.p, min(realsize, size));
        free(b.p);
        return;
    }

    fuse_reply_err(req, ENOENT);
}

static void smt_releasedir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {

    khint_t k = kh_get(opendirhash, opendirh, ino);
    if (k != kh_end(opendirh)) {
        struct opendirinfo *opendir = kh_val(opendirh, k);
        --opendir->openref;

        fuse_reply_err(req, 0);
    } else {
        fuse_reply_err(req, ENOENT);
    }
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
                ino = add_file(name, S_IFDIR | mode, config.blksize);
            }

            if (ino) {
                k = add_openfile(parent);
                if (k != kh_end(fcache)) {
                    struct openfileinfo *fp = kh_value(fcache, k);
                    if (parent != TAGS) {
                        add_filetodir(fp->name, ino);
                    }

                    k = add_openfile(ino);
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
        time(&lvisit.visits[opendir->index].visit);

        int pos = find_fname_pos(opendir->filenames, (char *)name);

        if (opendir->filenames->entries[pos].name && !strcmp(opendir->filenames->entries[pos].name, name)) {
            k = add_openfile(opendir->filenames->entries[pos].ino);
            if (k != kh_end(fcache)) {
                struct openfileinfo *f = kh_value(fcache, k);
                struct dirinfo *olddir = NULL;
                struct opendirinfo *openolddir = NULL;

                if (strncmp(name, newname, max(strlen(name), strlen(newname)))) {
                    if ((f->mode & S_IFMT) == S_IFDIR) {
                        k = kh_get(dirhash, dirh, newname);
                        if (k != kh_end(dirh)) {
                            fuse_reply_err(req, EEXIST);
                            return;
                        }

                        k = kh_get(dirhash, dirh, f->name);
                        if (k != kh_end(dirh)) {
                            olddir = kh_value(dirh, k);
                        }

                        k = add_opendir(f->ino);
                        if (k != kh_end(opendirh)) {
                            openolddir = kh_value(opendirh, k);
                        }
                    }

                    free(f->name);
                    f->name = (char*) malloc(strlen(newname)+1);
                    strncpy(f->name, newname, strlen(newname));
                    f->name[strlen(newname)] = '\0';

                    if ((f->mode & S_IFMT) == S_IFDIR) {
                        add_directory(f->name, olddir->ino);

                        for (int i = 0; i < openolddir->fileinos->size; i++) {
                            set_file_xattr(openolddir->fileinos->inos[i], f->name, ADD);
                            set_file_xattr(openolddir->fileinos->inos[i], name, RMV);
                        }

                        k = kh_get(dirhash, dirh, olddir->name);
                        kh_del(dirhash, dirh, k);
                        free(olddir->name);
                        free(olddir);
                    }

                    for (int i = 0; i < f->dirinos->size; i++) {
                        k = kh_get(opendirhash, opendirh, f->dirinos->inos[i]);
                        if (k != kh_end(opendirh)) {
                            refreshdir(f->dirinos->inos[i]);
                        }
                    }

                    clock_gettime(CLOCK_REALTIME, &f->ctime);

                    if (config.passthrough && (f->mode & S_IFMT) != S_IFDIR) {
                        rename_symlink(f->ino, f->name);
                    }
                }

                if (parent != newparent) {
                    if ((f->mode & S_IFMT) == S_IFDIR) {
                        res = recursive_dir(newparent, f->ino); //check for A->..->A circular relation
                        if (res) {
                            fuse_reply_err(req, res);
                            return;
                        }
                    }

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
    }

	fuse_reply_err(req, res);
}

static void smt_create(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode, struct fuse_file_info *fi) {
    struct fuse_entry_param e;
    memset(&e, 0, sizeof(e));

    khint_t k = add_openfile(parent);
    if (k != kh_end(fcache)) {
        struct openfileinfo *fp = kh_value(fcache, k);

        if (freemap->ino < MAX_FILES) {
            if (parent > TAGS && ((mode & S_IFMT) != S_IFDIR) && ((fp->mode & S_IFMT) == S_IFDIR)) {
                ino_t ino = add_file(name, S_IFREG | mode, 0x0);

                if (parent != FILES) {
                    add_filetodir(fp->name, ino);
                }

                k = add_openfile(ino);
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

    khint_t k = add_openfile(ino);
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
                    ++f->nref;
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

    khint_t k = add_openfile(ino);
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
        time(&lvisit.visits[opendir->index].visit);

        int pos = find_fname_pos(opendir->filenames, (char *)name);

        if (opendir->filenames->entries[pos].name && !strcmp(opendir->filenames->entries[pos].name, name)) {
            if (parent == FILES) { //if unlinking from _FILES, unlink from everywhere and free file
                res = remove_file(opendir->filenames->entries[pos].ino);
            } else {
                khint_t k = add_openfile(parent);
                if (k != kh_end(fcache)) {
                    struct openfileinfo *fp = kh_value(fcache, k);

                    remove_filefromdir(fp->name, opendir->filenames->entries[pos].ino);
                    res = 0;
                }
            }
        }
    }

	fuse_reply_err(req, res);
}

static void smt_rmdir(fuse_req_t req, fuse_ino_t parent, const char *name) {

    int res = ENOENT;
    khint_t k;

    k = add_opendir(parent);
    if (k != kh_end(opendirh)) {
        struct opendirinfo *dir = kh_value(opendirh, k);
        time(&lvisit.visits[dir->index].visit);

        int pos = find_fname_pos(dir->filenames, (char *)name);

        if (dir->filenames->entries[pos].name && !strcmp(dir->filenames->entries[pos].name, name)) {
            if (dir->filenames->entries[pos].ino > SYSDIR) {
                if (parent == TAGS) { //if unlinking from /, unlink from everywhere and free file
                    res = remove_file(dir->filenames->entries[pos].ino);
                } else { //else unlink only from current directory
                    k = add_openfile(parent);
                    if (k != kh_end(fcache)) {
                        struct openfileinfo *fp = kh_value(fcache, k);

                        remove_filefromdir(fp->name, dir->filenames->entries[pos].ino);
                        res = 0;
                    }
                }
            }  else {
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

    int res = close(dup(fi->fh)); //could use for diagnostics

    fuse_reply_err(req, res == -1 ? errno : 0);
}

static void smt_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {

    int res = 0;

    khint_t k = kh_get(openfilehash, fcache, ino);
    if (k != kh_end(fcache)) {
        struct openfileinfo *f = kh_value(fcache, k);
        --f->nref;
        res = close(fi->fh);
    } else {
        res = ENOENT;
    }

    fuse_reply_err(req, res == -1 ? errno : res);
}

static void smt_statfs(fuse_req_t req, fuse_ino_t ino) {

	struct statvfs stbuf;

	int res = fstatvfs(config.root_fd, &stbuf);
	stbuf.f_files = MAX_FILES;
	stbuf.f_ffree = stbuf.f_favail = MAX_FILES-config.used;

	if (res == -1)
		fuse_reply_err(req, errno);
	else
		fuse_reply_statfs(req, &stbuf);
}

static void smt_listxattr(fuse_req_t req, fuse_ino_t ino, size_t size) {

	char *value = NULL;
    ssize_t ret = 0;
    struct openfileinfo *f = NULL;

    khint_t k = add_openfile(ino);
    if (k != kh_end(fcache)) {
        f = kh_value(fcache, k);

        if (size) {
            value = (char *)malloc(size);
            if (!value) {
                fuse_reply_err(req, ENOMEM);
                return;
            }
            char *p = value;

            for (int i = 0; i < f->dirinos->size; i++) {
                k = kh_get(openfilehash, fcache, f->dirinos->inos[i]);
                if (k != kh_end(fcache)) {
                    struct openfileinfo *fd = kh_value(fcache, k);
                    p = memccpy(p, fd->name, '\0', strlen(fd->name)+1);
                } else {
                    char *dirname = get_xattr_from_file(f->dirinos->inos[i], "user.smtfs_m.name");
                    p = memccpy(p, dirname, '\0', strlen(dirname)+1);
                    free(dirname);
                }
            }

            fuse_reply_buf(req, value, size);
        } else {
            for (int i = 0; i < f->dirinos->size; i++) {
                k = kh_get(openfilehash, fcache, f->dirinos->inos[i]);
                if (k != kh_end(fcache)) {
                    struct openfileinfo *fd = kh_value(fcache, k);
                    ret += strlen(fd->name)+1;
                } else {
                    char *dirname = get_xattr_from_file(f->dirinos->inos[i], "user.smtfs_m.name");
                    ret += strlen(dirname)+1;
                    free(dirname);
                }
            }

            fuse_reply_xattr(req, ret);
        }
        free(value);
    }
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
        return ELOOP;
    }

    int saverr = 0;

    khint_t k = kh_get(openfilehash, fcache, dirino);
    if (k != kh_end(fcache)) {
        struct openfileinfo *f = kh_value(fcache, k);

        for (int i = 0; i < f->dirinos->size; i++) {
            saverr = recursive_dir(f->dirinos->inos[i], ino);
            if (saverr) {
                return saverr;
            }
        }
    } else {
        char *filepath = get_ino_path(config.storage, dirino);
        if (filepath) {
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
                                recursive_dir(dir->ino, ino);
                            }
                        }
                        s = strchr(s, '\0');
                        s++;
                    }
                }
                free(list);
            }
            free(filepath);
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

    khint_t k;
    k = kh_get(dirhash, dirh, name);

    if (k != kh_end(dirh)) {
        struct dirinfo *dir = kh_value(dirh, k);
        if (dir->ino == ROOT) {
            fuse_reply_err(req, saverr);
            return;
        }

        k = add_openfile(ino);
        if (k != kh_end(fcache)) {
            struct openfileinfo *f = kh_value(fcache, k);

            if ((f->mode & S_IFMT) != S_IFDIR && dir->ino == TAGS) {
                fuse_reply_err(req, saverr);
                return;
            }

            int pos = find_ino_pos(f->dirinos, dir->ino);
            if (f->dirinos->inos[pos] == dir->ino) { //check if dir being added is already present
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
        saverr = add_file(name, S_IFDIR | 0777, config.blksize);
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

        k = add_openfile(ino);
        if (k != kh_end(fcache)) {
            struct openfileinfo *f = kh_value(fcache, k);

            int pos = find_ino_pos(f->dirinos, dir->ino);
            if (f->dirinos->inos[pos] == dir->ino) { //check if present
                remove_filefromdir(name, ino);
                saverr = 0;
            }
        }
    }
    fuse_reply_err(req, saverr);
}

int is_dir_invalid(char* dirpath) {
    DIR *imfd = opendir(dirpath);
    if (imfd) {
        closedir(imfd);
        return 0;
    } else {
        printf("Requested path %s is not a directory\n", dirpath);
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
    .opendir = smt_opendir,
    .readdir = smt_readdir,
    .releasedir = smt_releasedir,
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
     SMTFS_OPT("clear=%s",          clear, 0),
     SMTFS_OPT("-p",                passthrough, 1),
     SMTFS_OPT("--passthrough",     passthrough, 1),
     SMTFS_OPT("-li",               refresh, 1),
     SMTFS_OPT("--list-imports",    refresh, 1),
     SMTFS_OPT("--dump",            dump, 1),
     FUSE_OPT_KEY("-V",             KEY_VERSION),
     FUSE_OPT_KEY("--version",      KEY_VERSION),
     FUSE_OPT_KEY("-h",             KEY_HELP),
     FUSE_OPT_KEY("--help",         KEY_HELP),
     FUSE_OPT_END
};

static int smtfs_opt_proc(void *data, const char *arg, int key, struct fuse_args *outargs) {
    return 1;
}

int main(int argc, char **argv) {
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
               "    -o import='source_dir[&dir2]'    import existing directories\n"
               "    -p   --passthrough               pass operations to the import directory\n"
               "    --dump                           export smtfs file tagging metadata to a text file and exit\n"
               "    -o clear='source_dir[&dir2]'     clear all smtfs xattrs from previous import directories and exit\n"
               "fuse options:\n");
        fuse_cmdline_help();
        fuse_lowlevel_help();

        free(opts.mountpoint);
        fuse_opt_free_args(&args);
        return 0;
    }

    if (opts.show_version) {
        printf("FUSE library version %s\n", fuse_pkgversion());
        fuse_lowlevel_version();

        free(opts.mountpoint);
        fuse_opt_free_args(&args);
        return 0;
    }

    if (opts.mountpoint == NULL) {
        printf("Usage: %s <mountpoint> [options]\n", argv[0]);

        free(opts.mountpoint);
        fuse_opt_free_args(&args);
        return 1;
    }

    conf.devfile = realpath(opts.mountpoint, NULL);
    if (!conf.devfile) {
        free(opts.mountpoint);
        fuse_opt_free_args(&args);
        return 1;
    }

    DIR *rootdir = opendir(conf.devfile);
    conf.root_fd = dirfd(rootdir);
    struct stat stbuf;
    memset(&stbuf, 0, sizeof(stbuf));
    fstat(conf.root_fd, &stbuf);
    conf.dev = stbuf.st_dev;
    conf.blksize = stbuf.st_blksize;

    char *storage = malloc(PATH_MAX);
    char *backup = malloc(PATH_MAX);
    char *dirpath = dirname(strdup(conf.devfile));
    if (storage && backup && dirpath) {
        storage[0] = '\0';
        strcat(storage, dirpath);
        strcat(storage, "/.smtfs_");
        strcat(storage, basename(conf.devfile));
        strcat(storage, "_storage");
        mkdir(storage, 0700);
        conf.storage = storage;

        backup[0] = '\0';
        strcat(backup, dirpath);
        strcat(backup, "/.smtfs_");
        strcat(backup, basename(conf.devfile));
        strcat(backup, "_backup");
        mkdir(backup, 0700);
        conf.backup = backup;
    } else {
        retval = 1;
        goto errlabel_three;
    }

    if (conf.dump) {
        export_metadata_txt(conf.devfile, storage);

        if (!conf.clear) {
            retval = 0;
            goto errlabel_three;
        }
    }

    if (conf.clear) {
        char *cleardir = conf.clear;
        if (strchr(conf.clear, '&')) {
            char *q = cleardir;
            while ((q = strchr(q, '&'))) {
                *q = '\0';
                if (!is_dir_invalid(cleardir)) {
                    remove_xattr_from_dir(cleardir);
                }
                *q = '&';
                cleardir = ++q;
            }
        }
        if (!is_dir_invalid(cleardir)) {
            remove_xattr_from_dir(cleardir);
        }
        printf("smtfs: Clear complete!\n");

        free(conf.clear);
        retval = 0;
        goto errlabel_three;
    }

    if (conf.import) { //check all import sources
        char *importdir = conf.import;
        if (strchr(conf.import, '&')) {
            char *q = importdir;
            while ((q = strchr(q, '&'))) {
                *q = '\0';
                if (is_dir_invalid(importdir)) {
                    retval = 1;
                    goto errlabel_three;
                }
                *q = '&';
                importdir = ++q;
            }
        }
        if (is_dir_invalid(importdir)) {
            retval = 1;
            goto errlabel_three;
        }
    }

    se = fuse_session_new(&args, &operations, sizeof(operations), &conf);
    if (se == NULL) {
        retval = 1;
        goto errlabel_three;
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

errlabel_three:
    free(opts.mountpoint);
    fuse_opt_free_args(&args);
    free(dirpath);
    free(conf.devfile);
    free(conf.import);
    free(conf.storage);
    free(conf.backup);
    closedir(rootdir);
    close(conf.root_fd);

    return retval;
}
