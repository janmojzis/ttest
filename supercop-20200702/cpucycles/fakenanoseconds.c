#include <time.h>

/* XXX Measured numbers are not CPU cycles but nanoseconds !!! */

static long long faketime = 0;

long long cpucycles_fakenanoseconds(void) {

    struct timespec t;
    long long tm;

    if (clock_gettime(CLOCK_MONOTONIC,&t) != 0) return -1;

    tm = t.tv_sec * 1000000000LL + t.tv_nsec;
    if (tm > faketime) faketime = tm;
    ++faketime;

    return faketime;
}

long long cpucycles_fakenanoseconds_persecond(void) {
    return 1000000000LL;
}
