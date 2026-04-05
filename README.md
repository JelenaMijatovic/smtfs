# smtfs
smtfs is a FUSE semantic file system that allows the user to organise their files using directories that function like tags. It is possible to both import existing directories into smtfs and create new files within smtfs. smtfs keeps track of the underlying file system in an unobtrusive manner through extended file attributes (xattr). 

smtfs requires a Linux system that supports extended file attributes and has [FUSE](https://github.com/libfuse/libfuse) installed. Currently developing on Linux Mint.

**Mounting**
```
 ./smtfs mount_location [-p|--passthrough] [-o import=source_directory]
```
The passthrough option enables the user to rename and delete files **in the source directory(!)** through smtfs.

Multiple source directories can be imported at once by appending them with '&' within single quotes:
```
 ./smtfs mount_location -o import='srcdir1&srcdir2'
```

**Unmounting**
```
 fusermount3 -u mount_location
```
**File operations**

Tagging is done through regular xattr operations (only the attribute name is relevant). It's also possible to tag files by "moving" them to the corresponding directory in a file manager, and undo tagging by deleting the file in the same directory.
Entirely removing a file or directory from smtfs is done via removing it in the /_FILES and /_TAGS directory respectively. Removing a directory doesn't remove the files contained in it.

**Notes**

smtfs uses [klib](https://github.com/attractivechaos/klib) (licensed under [MIT license](https://github.com/JelenaMijatovic/smtfs/blob/eaa99ad6db5ac75314d54dc59e0a37546cb05654/NOTICE.md)) for data structure implementation.
