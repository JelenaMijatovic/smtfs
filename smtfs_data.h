struct freeino *freemap;

khash_t(dirhash) *dirh;
khash_t(openfilehash) *fcache;
khash_t(opendirhash) *opendirh;

#define vst_lt(a, b) ((a).visit < (b).visit)
KSORT_INIT(vst, struct vst, vst_lt);
struct last_visited lvisit;
