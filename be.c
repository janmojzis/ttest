#include <stdint.h>
#include <stdio.h>

/* clang-format off */

typedef uint32_t vec32 __attribute__ ((vector_size (16)));

/* endianness */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define vec32_beswap(x) (x)
#else
vec32 vec32_beswap(vec32 u) {
    vec32 r;
    r[0] = __builtin_bswap32(u[0]);
    r[1] = __builtin_bswap32(u[1]);
    r[2] = __builtin_bswap32(u[2]);
    r[3] = __builtin_bswap32(u[3]);
    return r;
}
#endif

static uint32_t _bs(uint32_t u) {
    unsigned char x[4];
    x[0] = u; u >>= 8;
    x[1] = u; u >>= 8;
    x[2] = u; u >>= 8;
    x[3] = u;
    return *(uint32_t *)x;
}

int main() {

    unsigned char x[16] = {0, 1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15};
    vec32 r = *(vec32 *)x;
    vec32 z = {0, 1, 2, 3};

    printf("z: %u,%u,%u,%u\n", z[0], z[1], z[2], z[3]);
    z = vec32_beswap(z);
    printf("Z: %u,%u,%u,%u\n", z[0], z[1], z[2], z[3]);
    printf("r: %u,%u,%u,%u\n", r[0], r[1], r[2], r[3]);
    r = vec32_beswap(r);
    printf("R: %u,%u,%u,%u\n", r[0], r[1], r[2], r[3]);

    printf("%u,%u\n", 7, _bs(7));
}




