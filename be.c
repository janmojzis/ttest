#include <stdint.h>
#include <stdio.h>

/* clang-format off */

typedef uint32_t vec32 __attribute__ ((vector_size (16)));

/* endianness */
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define vec32_beswap(x) (x)
#else
vec32 vec32_beswap(vec32 u) {
    vec r;
    r[0] = __builtin_bswap32(u[3]);
    r[1] = __builtin_bswap32(u[2]);
    r[2] = __builtin_bswap32(u[1]);
    r[3] = __builtin_bswap32(u[0]);
    return r;
}
#endif

int main() {

    char x[16] = {0, 1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15};
    vec32 r = vec32_beswap(*(vec32 *)x);
    vec32 z = {0, 1, 2, 4};
    z = vec32_beswap(z);

    printf("%u,%u,%u,%u\n", r[0], r[1], r[2], r[3]);
    printf("%u,%u,%u,%u\n", z[0], z[1], z[2], z[3]);
}



