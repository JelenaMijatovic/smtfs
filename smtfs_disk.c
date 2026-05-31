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

//open/remove
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

//contents.txt
void write_dir_contents(ino_t dirino, struct inoarr *fileinos) {
    char *filepath = get_ino_path(config.storage, dirino);

    if (filepath) {
        strcat(filepath, "/contents.txt");

        int newfd = open(filepath, O_WRONLY | O_APPEND | O_TRUNC | O_CREAT, 0777);
        if (newfd) {
            for (int i = 0; i < fileinos->size; i++) {
                int length = snprintf(NULL, 0, "%ld\n", fileinos->inos[i]);
                char *strino = malloc(length+1);
                sprintf(strino, "%ld\n", fileinos->inos[i]);
                write(newfd, strino, length);
                free(strino);
            }
            close(newfd);
        } else {
            printf("write_dir_contents: Couldn't write to contents.txt for dir %ld!\n", dirino);
        }
        free(filepath);
    }
}

void append_dir_contents(ino_t dirino, ino_t fileino) {
    char *filepath = get_ino_path(config.storage, dirino);

    if (filepath) {
        strcat(filepath, "/contents.txt");

        int newfd = open(filepath, O_WRONLY | O_APPEND | O_CREAT, 0777);
        if (newfd) {
            int length = snprintf(NULL, 0, "%ld\n", fileino);
            char *strino = malloc(length+1);
            sprintf(strino, "%ld\n", fileino);
            write(newfd, strino, length);
            free(strino);
            close(newfd);
        } else {
            printf("append_dir_contents: Couldn't write to contents.txt for dir %ld!\n", dirino);
        }
        free(filepath);
    }
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

void export_metadata_txt(char* storagepath) {
    char *txtpath = get_file_path(devfile, "/datadump.txt");
    if (txtpath) {
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
            printf("smtfs: Dump finished! Created file datadump.txt\n");
        } else {
            printf("export_metadata_txt: Couldn't write text dump!\n");
        }
        free(txtpath);
        close(newfd);
    }
}
