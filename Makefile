src_files = smtfs_fuse.c smtfs_data.c smtfs_disk.c cp.c

smtfs: $(src_files) smtfs.h
	gcc -Wall -g $(src_files) `pkg-config fuse3 --cflags --libs` -o smtfs

clean:
	rm *.o smtfs
