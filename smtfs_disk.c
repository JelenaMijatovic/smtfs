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
