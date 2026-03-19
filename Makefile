smtfs: smtfs.c
	gcc -Wall smtfs.c `pkg-config fuse3 --cflags --libs` -o smtfs

clean:
	rm *.o smtfs
