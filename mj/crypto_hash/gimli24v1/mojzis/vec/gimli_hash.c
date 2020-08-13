/*
20200202
Jan Mojzis
Public domain.
*/

#include <stdint.h>
#include "crypto_hash.h"

/* clang-format off */

typedef uint32_t vec __attribute__ ((vector_size (16)));

static inline vec unpack(const unsigned char *x) {
    vec r;

    r[0] = (uint32_t) (x[ 0])                  \
       | (((uint32_t) (x[ 1])) << 8)           \
       | (((uint32_t) (x[ 2])) << 16)          \
       | (((uint32_t) (x[ 3])) << 24);
    r[1] = (uint32_t) (x[ 4])                  \
       | (((uint32_t) (x[ 5])) << 8)           \
       | (((uint32_t) (x[ 6])) << 16)          \
       | (((uint32_t) (x[ 7])) << 24);
    r[2] = (uint32_t) (x[ 8])                  \
       | (((uint32_t) (x[ 9])) << 8)           \
       | (((uint32_t) (x[10])) << 16)          \
       | (((uint32_t) (x[11])) << 24);
    r[3] = (uint32_t) (x[12])                  \
       | (((uint32_t) (x[13])) << 8)           \
       | (((uint32_t) (x[14])) << 16)          \
       | (((uint32_t) (x[15])) << 24);
    return r;
}

static inline void pack(unsigned char *x, vec u) {
    x[ 0] = u[0]; u[0] >>= 8;
    x[ 1] = u[0]; u[0] >>= 8;
    x[ 2] = u[0]; u[0] >>= 8;
    x[ 3] = u[0];
    x[ 4] = u[1]; u[1] >>= 8;
    x[ 5] = u[1]; u[1] >>= 8;
    x[ 6] = u[1]; u[1] >>= 8;
    x[ 7] = u[1];
    x[ 8] = u[2]; u[2] >>= 8;
    x[ 9] = u[2]; u[2] >>= 8;
    x[10] = u[2]; u[2] >>= 8;
    x[11] = u[2];
    x[12] = u[3]; u[3] >>= 8;
    x[13] = u[3]; u[3] >>= 8;
    x[14] = u[3]; u[3] >>= 8;
    x[15] = u[3];
}


#define ROTATE24(x) ((x) << ((vec){24,24,24,24})) ^ ((x) >> ((vec){ 8, 8, 8, 8}))
#define ROTATE09(x) ((x) << ((vec){ 9, 9, 9, 9})) ^ ((x) >> ((vec){23,23,23,23}))

#ifdef __clang__
#define vec_shuffle __builtin_shufflevector
#else
#define vec_shuffle __builtin_shuffle
#endif

static const vec c[6] = {
  (vec){ 0x9e377904, 0, 0, 0 },
  (vec){ 0x9e377908, 0, 0, 0 },
  (vec){ 0x9e37790c, 0, 0, 0 },
  (vec){ 0x9e377910, 0, 0, 0 },
  (vec){ 0x9e377914, 0, 0, 0 },
  (vec){ 0x9e377918, 0, 0, 0 },
} ;

#define GIMLI                                           \
                                                        \
    for (round = 5; round >= 0; --round) {              \
                                                        \
        x    = ROTATE24(x);                             \
        y    = ROTATE09(y);                             \
        newz = x ^ (z << 1) ^ ((y & z) << 2);           \
        newy = y ^ x        ^ ((x | z) << 1);           \
        x    = z ^ y        ^ ((x & y) << 3);           \
        y    = newy;                                    \
        z    = newz;                                    \
                                                        \
        x    = vec_shuffle(x, (vec){1, 0, 3, 2});       \
        x    ^= c[round];                               \
                                                        \
        x    = ROTATE24(x);                             \
        y    = ROTATE09(y);                             \
        newz = x ^ (z << 1) ^ ((y & z) << 2);           \
        newy = y ^ x        ^ ((x | z) << 1);           \
        x    = z ^ y        ^ ((x & y) << 3);           \
        y    = newy;                                    \
        z    = newz;                                    \
                                                        \
        x    = ROTATE24(x);                             \
        y    = ROTATE09(y);                             \
        newz = x ^ (z << 1) ^ ((y & z) << 2);           \
        newy = y ^ x        ^ ((x | z) << 1);           \
        x    = z ^ y        ^ ((x & y) << 3);           \
        y    = newy;                                    \
        z    = newz;                                    \
                                                        \
        x    = vec_shuffle(x, (vec){2, 3, 0, 1});       \
                                                        \
        x    = ROTATE24(x);                             \
        y    = ROTATE09(y);                             \
        newz = x ^ (z << 1) ^ ((y & z) << 2);           \
        newy = y ^ x        ^ ((x | z) << 1);           \
        x    = z ^ y        ^ ((x & y) << 3);           \
        y    = newy;                                    \
        z    = newz;                                    \
                                                        \
    }


int crypto_hash(unsigned char *o, const unsigned char *m, unsigned long long l) {

    unsigned char buf[48] = {0};
    vec x = (vec){ 0, 0, 0, 0 };
    vec y = (vec){ 0, 0, 0, 0 };
    vec z = (vec){ 0, 0, 0, 0 };
    vec newy, newz;
    long long i, round;

    /* absorb all the input blocks */
    while (l >= 16) {
        x ^= unpack(m);
        GIMLI;
        l -= 16;
        m += 16;
    }

    /* last block and padding */
    for (i = 0; i < l; ++i) buf[i] = m[i];
    buf[i] = 1;
    buf[sizeof buf - 1] = 1;
    x ^= unpack(buf);
    y ^= unpack(buf + 16);
    z ^= unpack(buf + 32);

    /* output */
    GIMLI;
    pack(o     , x);
    GIMLI;
    pack(o + 16, x);
    return 0;
}
/* clang-format off */
