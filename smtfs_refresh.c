#include "smtfs.h"

void* refresh_cache(void* arg) {

    while (1) {
        sleep(REFRESH_PERIOD);

        for (khint_t k = 0; k < kh_end(fcache); ++k)
            if (kh_exist(fcache, k)) {
                struct openfileinfo *f = kh_val(fcache, k);
                //printf("%s %ld\n", f->name, f->visit);
                if (f->ino != ROOT && time(NULL)-f->visit > REFRESH_PERIOD) {
                    remove_openfile(f->ino, k);
                }
            }
        //printf("\n");

    }

    return NULL;
}
