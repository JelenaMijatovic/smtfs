#include "smtfs.h"

struct freeino *freemap;

khash_t(dirhash) *dirh;
khash_t(openfilehash) *fcache;
khash_t(opendirhash) *opendirh;

#define vst_lt(a, b) ((a).visit < (b).visit)
KSORT_INIT(vst, struct vst, vst_lt);
struct last_visited lvisit;

//inoarr
int find_ino_pos(struct inoarr *inos, ino_t ino) {
    int l = 0;
    int r = inos->size-1;
    int pos = 0;
    while (l <= r) {
        pos = l + (r-l)/2;
        if (inos->inos[pos] < ino) {
            l = pos + 1;
        } else if (inos->inos[pos] > ino) {
            r = pos - 1;
        } else {
            break;
        }
    }
    return pos;
}

ino_t insert_ino(struct inoarr *inos, ino_t ino) {
    if (inos->size == 0) {
        inos->inos[0] = ino;
        inos->size++;
        return ino;
    }
    int pos = find_ino_pos(inos, ino);
    if (inos->inos[pos] != ino) {
        inos->size++;
        if (inos->size > inos->exp) {
            inos->exp *= 2;
            ino_t *newinos = realloc(inos->inos, sizeof(ino_t)*inos->exp);
            if (newinos) {
                memset(newinos + inos->size-1, 0x0, sizeof(ino_t)*(inos->exp - inos->size));
                inos->inos = newinos;
            } else {
                inos->exp /= 2;
                inos->size--;
                return 0;
            }
        }
        if (inos->inos[pos] > ino) {
            memcpy(&inos->inos[pos+1], &inos->inos[pos], sizeof(ino_t)*(inos->size - pos-1));
            inos->inos[pos] = ino;
        } else {
            if (pos+2 < inos->exp) {
                memcpy(&inos->inos[pos+2], &inos->inos[pos+1], sizeof(ino_t)*(inos->size - pos-2));
            }
            inos->inos[pos+1] = ino;
        }
    }
    return ino;
}

ino_t remove_ino(struct inoarr *inos, ino_t ino) {
    if (inos->size < 1) {
        return 0;
    }
    int pos = find_ino_pos(inos, ino);
    if (inos->inos[pos] == ino) {
        inos->size--;
        if (inos->size < inos->exp/2 && inos->exp > 2) {
            inos->exp /= 2;
            ino_t *newinos = realloc(inos->inos, sizeof(ino_t)*inos->exp);
            if (newinos) {
                inos->inos = newinos;
            } else {
                inos->size++;
                inos->exp *= 2;
                return 0;
            }
        }
        memcpy(&inos->inos[pos], &inos->inos[pos+1], sizeof(ino_t)*(inos->size-pos));
        return ino;
    } else {
        return 0;
    }
}

//strarr
int find_fname_pos(struct strarr *entries, char *fname) {
    int l = 0;
    int r = entries->size-1;
    int pos = 0;
    int res;
    while (l <= r) {
        pos = l + (r-l)/2;
        res = strcmp(entries->entries[pos].name, fname);
        if (res < 0) {
            l = pos + 1;
        } else if (res > 0) {
            r = pos - 1;
        } else {
            break;
        }
    }
    return pos;
}

ino_t insert_fname(struct strarr *entries, char *fname, ino_t ino) {
    printf("insert %s\n", fname);
    if (entries->size == 0) {
        entries->entries[0].name = fname;
        entries->entries[0].ino = ino;
        entries->size++;
        return ino;
    }
    int pos = find_fname_pos(entries, fname);
    int res = strcmp(entries->entries[pos].name, fname);
    printf("%s res %d\n", entries->entries[pos].name, res);
    if (res) {
        entries->size++;
        if (entries->size > entries->exp) {
            entries->exp *= 2;
            struct opendirentry *newentries = realloc(entries->entries, sizeof(struct opendirentry)*entries->exp);
            if (newentries) {
                memset(newentries + entries->size-1, 0x0, sizeof(struct opendirentry)*(entries->exp - entries->size));
                entries->entries = newentries;
            } else {
                entries->exp /= 2;
                entries->size--;
                return 0;
            }
        }
        if (res > 0) {
            memcpy(&entries->entries[pos+1], &entries->entries[pos], sizeof(struct opendirentry)*(entries->size - pos-1));
            entries->entries[pos].name = fname;
            entries->entries[pos].ino = ino;
        } else {
            if (pos+2 < entries->exp) {
                memcpy(&entries->entries[pos+2], &entries->entries[pos+1], sizeof(struct opendirentry)*(entries->size - pos-2));
            }
            entries->entries[pos+1].name = fname;
            entries->entries[pos+1].ino = ino;
        }
    }
    return ino;
}

ino_t remove_fname(struct strarr *entries, char *fname) {
    if (entries->size < 1) {
        return 0;
    }
    int pos = find_fname_pos(entries, fname);
    if (!strcmp(entries->entries[pos].name, fname)) {
        ino_t ino = entries->entries[pos].ino;
        free(entries->entries[pos].name);
        entries->size--;
        if (entries->size < entries->exp/2 && entries->exp > 2) {
            entries->exp /= 2;
            struct opendirentry *newentries = realloc(entries->entries, sizeof(struct opendirentry)*entries->exp);
            if (newentries) {
                entries->entries = newentries;
            } else {
                entries->size++;
                entries->exp *= 2;
                return 0;
            }
        }
        memcpy(&entries->entries[pos], &entries->entries[pos+1], sizeof(struct opendirentry)*(entries->size-pos));
        return ino;
    } else {
        return 0;
    }
}

//dirinfo
struct dirinfo* add_directory(const char* name, ino_t ino) {

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

void remove_directory(const char *name) {
    khint_t k, ko;

    k = kh_get(dirhash, dirh, name);
    if (k != kh_end(dirh)) {
        struct dirinfo *dir = kh_val(dirh, k);

        ko = add_opendir(dir->ino);
        struct opendirinfo *opendir = kh_val(opendirh, ko);

        for (int i = 0; i < opendir->fileinos->size; i++) {
            remove_filefromdir(name, opendir->fileinos->inos[0]);
        }

        remove_opendir(dir->ino);
        kh_del(dirhash, dirh, k);
        free(dir->name);
        free(dir);
    }
}

//opendirinfo <-> openfileinfo
int add_filetodir(const char *dirname, ino_t fileino) {

    khint_t k;

    k = kh_get(dirhash, dirh, dirname);
    if (k != kh_end(dirh)) {
        struct dirinfo *dir = kh_val(dirh, k);

        k = add_opendir(dir->ino);
        struct opendirinfo *opendir = kh_val(opendirh, k);

		if (opendir->fileinos->size >= MAX_DIRSIZE) {
            return ENOSPC;
        }

        //link directory and file both ways
        ino_t i = insert_ino(opendir->fileinos, fileino);
        if (i) {

            k = kh_get(openfilehash, fcache, fileino);
            if (k != kh_end(fcache)) {
                struct openfileinfo *f = kh_value(fcache, k);
                f->nref++;

                insert_ino(f->dirinos, dir->ino);
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
                set_file_xattr(fileino, f1->name, ADD);
            }

            refreshdir(NULL, NULL, dir->ino, 0);
            return 0;
        } else {
            return EEXIST;
        }
    }

    return ENOENT;
}

void remove_filefromdir(const char *dirname, ino_t fileino) {
    khint_t k;

    k = kh_get(dirhash, dirh, dirname);
    if (k != kh_end(dirh)) {
        struct dirinfo *dir = kh_val(dirh, k);

        k = add_opendir(dir->ino);
        struct opendirinfo *opendir = kh_val(opendirh, k);

        remove_ino(opendir->fileinos, fileino);

        k = kh_get(openfilehash, fcache, fileino);
        if (k != kh_end(fcache)) {
            struct openfileinfo *f = kh_value(fcache, k);
            f->nref--;

            remove_ino(f->dirinos, dir->ino);
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
            set_file_xattr(fileino, f1->name, RMV);
        }

        refreshdir(NULL, NULL, dir->ino, 0);
    }
}

//setup helper
int add_sysdirs(const char *name, mode_t mode) {
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
            f->dirinos = malloc(sizeof(struct inoarr));
            f->dirinos->inos = malloc(sizeof(ino_t)*2);
            memset(f->dirinos->inos, 0x0, sizeof(ino_t)*2);
            f->dirinos->size = 0;
            f->dirinos->exp = 2;
            clock_gettime(CLOCK_REALTIME, &f->atime);
            clock_gettime(CLOCK_REALTIME, &f->mtime);
            clock_gettime(CLOCK_REALTIME, &f->ctime);
            clock_gettime(CLOCK_REALTIME, &f->btime);
            f->nref = 0;

            int absent;
            khint_t k = kh_put(openfilehash, fcache, f->ino, &absent);
            kh_val(fcache, k) = f;

            struct dirinfo *ret = add_directory(name, freemap->ino);
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

//openfileinfo
ino_t add_file(const char *name, mode_t mode, off_t size) {

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
            f->nref = 0;
            f->dirinos = malloc(sizeof(struct inoarr));
            f->dirinos->inos = malloc(sizeof(ino_t)*2);
            memset(f->dirinos->inos, 0x0, sizeof(ino_t)*2);
            f->dirinos->size = 0;
            f->dirinos->exp = 2;

            clock_gettime(CLOCK_REALTIME, &f->atime);
            clock_gettime(CLOCK_REALTIME, &f->mtime);
            clock_gettime(CLOCK_REALTIME, &f->ctime);
            clock_gettime(CLOCK_REALTIME, &f->btime);

            int absent;
            khint_t k = kh_put(openfilehash, fcache, f->ino, &absent);
            kh_val(fcache, k) = f;

            if ((mode & S_IFMT) == S_IFDIR) {
                struct dirinfo *ret = add_directory(name, freemap->ino);
                if (!ret || add_filetodir(TAGS_FN, freemap->ino)) { //_TAGS contains all directories except those in root
                    if (ret) {
                        remove_directory(name);
                    }
                    free(f->name);
                    free(f->dirinos->inos);
                    free(f->dirinos);
                    free(f);
                    return 0;
                }
            } else {
                if (add_filetodir(FILES_FN, freemap->ino)) { //_FILES contains all regular files
                    free(f->name);
                    free(f->dirinos->inos);
                    free(f->dirinos);
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

void remove_file(ino_t ino) {
    khint_t k, k1;

    k = add_openfile(ino);
    if (k != kh_end(fcache)) {
        struct openfileinfo *f = kh_value(fcache, k);
        while (f->dirinos->size) {
            k1 = add_openfile(f->dirinos->inos[0]);
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
            free(f->dirinos->inos);
            free(f->dirinos);
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

        f->dirinos = malloc(sizeof(struct inoarr));
        f->dirinos->inos = malloc(sizeof(ino_t)*2);
        memset(f->dirinos->inos, 0x0, sizeof(ino_t)*2);
        f->dirinos->size = 0;
        f->dirinos->exp = 2;

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
                            insert_ino(f->dirinos, dir->ino);
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
            free(f->dirinos->inos);
            free(f->dirinos);
            free(f);
            kh_del(openfilehash, fcache, k);
        }
    }
}

//opendirinfo
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

                    dir->fileinos = malloc(sizeof(struct inoarr));
                    dir->fileinos->inos = malloc(sizeof(ino_t)*2);
                    memset(dir->fileinos->inos, 0x0, sizeof(ino_t)*2);
                    dir->fileinos->size = 0;
                    dir->fileinos->exp = 2;

                    dir->filenames = malloc(sizeof(struct strarr));
                    dir->filenames->entries = malloc(sizeof(struct opendirentry)*2);
                    memset(dir->filenames->entries, 0x0, sizeof(struct opendirentry)*2);
                    dir->filenames->size = 0;
                    dir->filenames->exp = 2;

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
                                insert_ino(dir->fileinos, fino);
                            }
                            fclose(fptr);
                        }
                    } else {
                        fatal_error("add_opendir: Couldn't allocate memory\n");
                    }
                    if (ino != FILES && ino != TAGS) { //!loading files for these two would be like loading in the entire FS
                        khint_t k;
                        for (int i = 0; i < dir->fileinos->size; i++) {
                            k = kh_get(openfilehash, fcache, dir->fileinos->inos[i]);
                            if (k == kh_end(fcache)) {
                                add_openfile(dir->fileinos->inos[i]);
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

void remove_opendir(ino_t ino) {
    khint_t k;

    k = kh_get(opendirhash, opendirh, ino);
    if (k != kh_end(opendirh)) {
        struct opendirinfo *opendir = kh_val(opendirh, k);
        lvisit.currindex = opendir->index;

        write_dir_contents(ino, opendir->fileinos);

        for (int i = 0; i < opendir->fileinos->size; i++) {
            remove_openfile(opendir->fileinos->inos[i]);
        }
        remove_openfile(ino);

        free(opendir->fileinos->inos);
        free(opendir->fileinos);
        for (int i = 0; i < opendir->filenames->size; i++) {
            free(opendir->filenames->entries[i].name);
        }
        free(opendir->filenames->entries);
        free(opendir->filenames);
        free(opendir);

        kh_del(opendirhash, opendirh, ino);
    }
}

//set operations
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

    if (d1 && d2) {
        switch (name[(pos-name)+1]) {
            case '&':{
                        ino_t ino = add_file(name, S_IFDIR | 0777, config.blksize);

                        for (int i = 0; i < d1->fileinos->size; i++) {
                            int pos = find_ino_pos(d2->fileinos, d1->fileinos->inos[i]);
                            if (d2->fileinos->inos[pos] == d1->fileinos->inos[i]) {
                                add_filetodir(name, d1->fileinos->inos[i]);
                            }
                        }

                        return ino;
                    }
            case '|':{
                        ino_t ino = add_file(name, S_IFDIR | 0777, config.blksize);

                        for (int i = 0; i < d1->fileinos->size; i++) {
                            add_filetodir(name, d1->fileinos->inos[i]);
                        }
                        for (int i = 0; i < d2->fileinos->size; i++) {
                            add_filetodir(name, d2->fileinos->inos[i]);
                        }

                        return ino;
                    }
            case '^':{
                        ino_t ino = add_file(name, S_IFDIR | 0777, config.blksize);

                        for (int i = 0; i < d1->fileinos->size; i++) {
                            int pos = find_ino_pos(d2->fileinos, d1->fileinos->inos[i]);
                            if (d2->fileinos->inos[pos] != d1->fileinos->inos[i]) {
                                add_filetodir(name, d1->fileinos->inos[i]);
                            }
                        }
                        for (int i = 0; i < d2->fileinos->size; i++) {
                            int pos = find_ino_pos(d1->fileinos, d2->fileinos->inos[i]);
                            if (d1->fileinos->inos[pos] != d2->fileinos->inos[i]) {
                                add_filetodir(name, d2->fileinos->inos[i]);
                            }
                        }

                        return ino;
                    }
            case '~':{
                        ino_t ino = add_file(name, S_IFDIR | 0777, config.blksize);

                        for (int i = 0; i < d1->fileinos->size; i++) {
                            int pos = find_ino_pos(d2->fileinos, d1->fileinos->inos[i]);
                            if (d2->fileinos->inos[pos] != d1->fileinos->inos[i]) {
                                add_filetodir(name, d1->fileinos->inos[i]);
                            }
                        }

                        return ino;
                    }
            default: return 0;
        }
    }
    return 0;
}
