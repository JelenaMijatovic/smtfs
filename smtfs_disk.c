#include "smtfs.h"

//filepath building helpers
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

char* get_err_path(int err) {
    char *filepath = malloc(PATH_MAX);
    if (filepath) {
        filepath[0] = '\0';
        strcat(filepath, config.errpath);
        int length = snprintf(NULL, 0, "/%d", err);
        char *strnum = malloc(length+1);
        sprintf(strnum, "/%d", err);
        strcat(filepath, strnum);
        free(strnum);
    }
    return filepath;
}

//xattr
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

void set_file_xattr(ino_t ino, const char *tag, int mode) {

    char *filepath = get_ino_path(config.storage, ino);
    char *name = malloc(PATH_MAX);

    if (filepath && name) {
        name[0] = '\0';
        strcat(name, "user.smtfs.");
        int length = snprintf(NULL, 0, "%s", tag);
        char *strino = malloc(length+1);
        sprintf(strino, "%s", tag);
        strcat(name, strino);
        free(strino);

        if (mode == ADD) {
            setxattr(filepath, name, "", 0, 0);
        } else {
            removexattr(filepath, name);
        }
        free(name);
    }
    free(filepath);
}

//open/remove
int open_file(ino_t ino, const char* name, mode_t mode) {
    int newfd = 0;
    char *filepath = get_ino_path(config.storage, ino);

    if (filepath) {
        //create the right directory in storage if not already present
        char *dirpath = dirname(strdup(filepath));
        mkdir(dirpath, 0700);

        //create file or directory, set name and nlink count as xattrs
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
        free(dirpath);
        free(filepath);
    }

    return newfd;
}

void set_file_attributes(struct openfileinfo *f) {
	char *filepath = get_ino_path(config.storage, f->ino);
    if (filepath) {
        int res1 = setxattr(filepath, "user.smtfs_m.name", f->name, strlen(f->name)+1, 0);

        if (res1) {
            printf("set_file_attributes: Failed to set xattr user.smtfs_m.name for file %ld, code %d. Logging error...\n", f->ino, errno);
            write_error_file(f->ino, SETNAMEXATTRERR, f->name);
		}

        int res2 = setxattr(filepath, "user.smtfs_m.nlink", &f->nlink, sizeof(f->nlink), 0);

		if (res2) {
            printf("set_file_attributes: Failed to set xattr user.smtfs_m.nlink for file %ld, code %d. Logging error...\n", f->ino, errno);
            write_error_file(f->ino, SETNLINKXATTRERR, &f->nlink);
		}

        struct timespec times[2];
        times[0].tv_sec = f->atime.tv_sec;
        times[0].tv_nsec = f->atime.tv_nsec;
        times[1].tv_sec = f->mtime.tv_sec;
        times[1].tv_nsec = f->mtime.tv_nsec;
        int res3 = utimensat(AT_FDCWD, filepath, times, AT_SYMLINK_NOFOLLOW);

		if (res3) {
            printf("set_file_attributes: Failed to set timestamp for file %ld, code %d. Logging error...\n", f->ino, errno);
            write_error_file(f->ino, TIMESETERR, times);
		}

        free(filepath);
    }
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

        //remove from storage
        if ((stbuf.st_mode & S_IFMT) == S_IFDIR) {
            char *contents = get_file_path(filepath, "/contents.txt");
            if (contents) {
                remove(contents);
                free(contents);
            }
        }
        remove(filepath);

        free(filepath);
    }
}

//symlink
void create_symlink(ino_t ino, char* name, char* target) {
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

//root: parent directory of file to write into
//filename: base name of file to write directory inodes into.
//returns 0 on success, nonzero on failure
int write_dirinos_into_file(char *root, char *filename) {

    char *filepath;
    if (!strncmp(root, config.errpath, strlen(config.errpath))) {
        filepath = get_err_path(config.errcount);
    } else {
        filepath = get_file_path(root, filename);
    }
    int res = -1, err = 0;

    if (filepath) {
        int newfd = open(filepath, O_WRONLY | O_TRUNC | O_CREAT, 0777);

        if (newfd) {
            char *strino;

            for (khint_t k = 0; k < kh_end(dirh); ++k) {
                if (kh_exist(dirh, k)) {
                    struct dirinfo* dir = kh_val(dirh, k);
                    int length = snprintf(NULL, 0, "%ld\n", dir->ino);
                    strino = malloc(length+1);
                    sprintf(strino, "%ld\n", dir->ino);
                    write(newfd, strino, length);
                    free(strino);

                }
            }
            res = close(newfd);
            err = errno;
        }
        free(filepath);
    }

    if (res && strncmp(root, config.errpath, strlen(config.errpath))) {
        printf("write_dirinos_into_file: Failed to write directory inodes into file %s, code %d. Logging error...\n", filename, err);
        write_error_file(0, DIRINOERR, NULL);
    }

    return res;
}

//root: parent directory of file to write into
//filename: base name of file to write free inodes into.
//returns 0 on success, nonzero on failure
int write_freemap_into_file(char *root, char *filename) {

    char *filepath;
    if (!strncmp(root, config.errpath, strlen(config.errpath))) {
        filepath = get_err_path(config.errcount);
    } else {
        filepath = get_file_path(root, filename);
    }
    int res = -1, err = 0;

    if (filepath) {
        int newfd = open(filepath, O_WRONLY | O_TRUNC | O_CREAT, 0777);
        if (newfd) {
            int length;
            char *strino;

            length = snprintf(NULL, 0, "%ld\n", config.used);
            strino = malloc(length+1);
            sprintf(strino, "%ld\n", config.used);
            write(newfd, strino, length);
            free(strino);

            struct freeino *curr = freemap;
            while (curr) {
                length = snprintf(NULL, 0, "%ld\n", curr->ino);
                strino = malloc(length+1);
                sprintf(strino, "%ld\n", curr->ino);
                write(newfd, strino, length);
                free(strino);
                curr = curr->nextfr;
            }
            res = close(newfd);
            err = errno;
        }
        free(filepath);
    }

    if (res && strncmp(root, config.errpath, strlen(config.errpath))) {
        printf("write_freemap_into_file: Failed to write freemap into file %s, code %d. Logging error...\n", filename, err);
        write_error_file(0, FREEMAPERR, NULL);
    }

    return res;
}

//dirino: inode of directory whose contents to write on disk. If negative, treated as error counter
//fileinos: array of inodes to write into contents.txt
//returns 0 on success, nonzero on failure
int write_dir_contents(ino_t dirino, struct inoarr *fileinos) {

    char *filepath;
    int res = -1;
    int err = 0;

    if (dirino > 0) {
        filepath = get_ino_path(config.storage, dirino);
    } else {
        filepath = get_err_path(-dirino);
    }

    if (filepath) {
        if (dirino > 0) {
            strcat(filepath, "/contents.txt");
        }

        int newfd = open(filepath, O_WRONLY | O_APPEND | O_TRUNC | O_CREAT, 0777);
        if (newfd) {
            for (int i = 0; i < fileinos->size; i++) {
                int length = snprintf(NULL, 0, "%ld\n", fileinos->inos[i]);
                char *strino = malloc(length+1);
                sprintf(strino, "%ld\n", fileinos->inos[i]);
                write(newfd, strino, length);
                free(strino);
            }
            res = close(newfd);
            err = errno;
        }
        free(filepath);
    }

    if (res && dirino > 0) {
        printf("write_dir_contents: Failed to write directory contents to disk for dir %ld, code %d. Logging error...\n", dirino, err);
        write_error_file(dirino, DIRCONTERR, fileinos);
    }

    return res;
}

int append_dir_contents(ino_t dirino, ino_t fileino) {

    char *filepath = get_ino_path(config.storage, dirino);
    int res = -1;

    if (filepath) {
        strcat(filepath, "/contents.txt");

        int newfd = open(filepath, O_WRONLY | O_APPEND | O_CREAT, 0777);
        if (newfd) {
            int length = snprintf(NULL, 0, "%ld\n", fileino);
            char *strino = malloc(length+1);
            sprintf(strino, "%ld\n", fileino);
            write(newfd, strino, length);
            free(strino);

            res = close(newfd);
        }
        free(filepath);
    }

    return res;
}

void remove_xattr_from_dir(char* dirpath) {

    struct stat stbuf;
    memset(&stbuf, 0, sizeof(stbuf));

    stat(dirpath, &stbuf);
    if ((stbuf.st_mode & S_IFMT) == S_IFDIR) {
        DIR *imfd = opendir(dirpath);
        if (imfd) {
            int size;
            struct dirent *entry = NULL;
            while ((entry = readdir(imfd)) != NULL) {
                char *entrpath = malloc(PATH_MAX);
                if (entrpath) {
                    entrpath[0] = '\0';
                    strcat(entrpath, dirpath);

                    strcat(entrpath, "/");
                    strcat(entrpath, entry->d_name);
                    if (strncmp(entry->d_name, ".", strlen(entry->d_name)) && strncmp(entry->d_name, "..", strlen(entry->d_name))) {
                        size = listxattr(entrpath, 0, 0);
                        if (size > 0) {
                            char* list = malloc(size);
                            if (list) {
                                listxattr(entrpath, list, size);
                                int sum = 0;
                                char *s = list;
                                char *p;
                                while (sum < size) {
                                    sum += strlen(s)+1;
                                    p = strstr(s, "user.smtfs");
                                    if (p) {
                                        removexattr(entrpath, p);
                                    }
                                    s = strchr(s, '\0');
                                    s++;
                                }
                                free(list);
                            }
                        }

                        remove_xattr_from_dir(entrpath);
                    }

                    free(entrpath);
                }
            }
            closedir(imfd);
        } else {
            printf("remove_xattr_from_dir: Couldn't open directory.\n");
        }
    }
}

void export_metadata_txt(char* devfile, char* storagepath) {
    char *txtpath = malloc(PATH_MAX);
    char *dirpath = dirname(strdup(devfile));
    if (txtpath) {
        txtpath[0] = '\0';
        strcat(txtpath, dirpath);
        strcat(txtpath, "/");
        strcat(txtpath, basename(devfile));
        strcat(txtpath, "_datadump.txt");

        int newfd = open(txtpath, O_WRONLY | O_TRUNC | O_CREAT, 0777);
        if (newfd) {
            char *filepath = NULL;
            for (int i = 0; i <= 99; i++) {
                filepath = malloc(PATH_MAX);
                if (filepath) {
                    filepath[0] = '\0';
                    strcat(filepath, storagepath);
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
                                ino_t ino;
                                sscanf(entry->d_name, "%ld", &ino);
                                int length = snprintf(NULL, 0, "%ld ", ino);
                                strino = malloc(length+1);
                                sprintf(strino, "%ld ", ino);

                                write(newfd, strino, length);
                                free(strino);

                                char *entrpath = get_ino_path(storagepath, ino);
                                if (entrpath) {
                                    lstat(entrpath, &stbuf);
                                    int size = getxattr(entrpath, "user.smtfs_m.name", 0, 0);
                                    if (size > 0) {
                                        char* name = malloc(size);
                                        getxattr(entrpath, "user.smtfs_m.name", name, size);

                                        write(newfd, name, strlen(name));
                                        write(newfd, " ", 1);

                                        free(name);
                                    }

                                    if ((stbuf.st_mode & S_IFMT) == S_IFDIR) {
                                        write(newfd, "DIR ", strlen("DIR "));
                                    } else if ((stbuf.st_mode & S_IFMT) == S_IFLNK) {
                                        write(newfd, "LNK ", strlen("LNK "));
                                        char *buf = malloc(stbuf.st_size + 1);
                                        readlink(entrpath, buf, stbuf.st_size);
                                        buf[stbuf.st_size] = ' ';

                                        write(newfd, buf, stbuf.st_size);

                                        free(buf);
                                    } else {
                                        write(newfd, "REG ", strlen("LNK "));
                                    }

                                    size = listxattr(entrpath, 0, 0);
                                    if (size > 0) {
                                        char* list = malloc(size);
                                        if (list) {
                                            listxattr(entrpath, list, size);
                                            int sum = 0;
                                            char *s = list;
                                            char *p;
                                            while (sum < size) {
                                                sum += strlen(s)+1;
                                                p = strstr(s, "user.smtfs.");
                                                if (p) {
                                                    p = p + strlen("user.smtfs.");
                                                    write(newfd, p, strlen(p));
                                                    write(newfd, " ", 1);
                                                }
                                                s = strchr(s, '\0');
                                                s++;
                                            }
                                            free(list);
                                        }
                                    }
                                    memset(&stbuf, 0, sizeof(stbuf));
                                    free(entrpath);
                                }
                                write(newfd, "\n", 1);
                            }
                        }
                        closedir(imfd);
                    }
                    free(filepath);
                }
            }
            printf("smtfs: Dump finished! Created file %s\n", txtpath);
        } else {
            printf("export_metadata_txt: Couldn't write text dump!\n");
        }
        free(txtpath);
        close(newfd);
    }
    free(dirpath);
}

void write_error_file(ino_t ino, int errtype, void *data) {

    int res = -1;

    mkdir(config.errpath, 0700);

    char *filepath = get_err_path(++config.errcount);
    if (filepath) {

        int fd = open(filepath, O_WRONLY | O_APPEND | O_TRUNC | O_CREAT, 0777);

        if (fd != -1) {
            int temp = errtype;

            int res1 = setxattr(filepath, "user.smtfs_m.ino", &ino, sizeof(ino_t), 0);
            int res2 = setxattr(filepath, "user.smtfs_m.error", &temp, sizeof(int), 0);

            switch (errtype) {
                case DIRCONTERR: {

                    int res3 = write_dir_contents(-config.errcount, data);

                    res = res1 | res2 | res3;
                    break;
                }
                case SETNAMEXATTRERR: {

                    int res3 = setxattr(filepath, "user.smtfs_m.data", data, strlen(data)+1, 0);

                    res = res1 | res2 | res3;
                    break;
                }
                case SETNLINKXATTRERR: {

                    int res3 = setxattr(filepath, "user.smtfs_m.data", data, sizeof(int), 0);

                    res = res1 | res2 | res3;
                    break;
                }
                case TIMESETERR: {

                    int res3 = setxattr(filepath, "user.smtfs_m.data", data, 2*sizeof(struct timespec), 0);

                    res = res1 | res2 | res3;
                    break;
                }
                case DIRINOERR: {

                    int res3 = write_dirinos_into_file(config.errpath, 0);

                    res = res1 | res2 | res3;
                    break;
                }
                case FREEMAPERR: {

                    int res3 = write_freemap_into_file(config.errpath, 0);

                    res = res1 | res2 | res3;
                    break;
                }
            }
        }

        free(filepath);
    }

    if (res) {
        printf("WARNING: Failed to log error; data loss is likely. It's recommended you restart smtfs as soon as possible.");
    }
}
