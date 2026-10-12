struct freeino *freemap; //global freemap

//khash global hashmaps
khash_t(dirhash) *dirh;         //unique directory filename -> inode
khash_t(openfilehash) *fcache;  //inode -> file info
khash_t(opendirhash) *opendirh; //inode -> directory info, max size MAX_OPEN

//ksort sorting functions included for ks_ksmall sort of lvisit by timestamp
#define vst_lt(a, b) ((a).visit < (b).visit)
KSORT_INIT(vst, struct vst, vst_lt);

struct last_visited lvisit; //global array of timestamps for directories in opendirh, size MAX_OPEN
