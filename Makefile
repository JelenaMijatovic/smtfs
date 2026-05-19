src_files = smtfs_fuse.c smtfs_data.c smtfs_disk.c cp.c

smtfs: $(src_files) smtfs.h
	gcc -Wall $(src_files) `pkg-config fuse3 --cflags --libs` -I./klib -o smtfs

clean:
	rm *.o smtfs
