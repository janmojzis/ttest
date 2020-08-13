/*
20200202
Jan Mojzis
Public domain.
*/

#include <stdint.h>
#include "crypto_stream.h"

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


#define ROTATE(x, c) ((x) << (c)) ^ ((x) >> (32 - (c)))

#ifdef __clang__
#define vec_shuffle __builtin_shufflevector
#else
#define vec_shuffle __builtin_shuffle
#endif

static const vec rc[6] = {
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
        x    = ROTATE(x, 24);                           \
        y    = ROTATE(y,  9);                           \
        newz = x ^ (z << 1) ^ ((y & z) << 2);           \
        newy = y ^ x        ^ ((x | z) << 1);           \
        x    = z ^ y        ^ ((x & y) << 3);           \
        y    = newy;                                    \
        z    = newz;                                    \
                                                        \
        x    = vec_shuffle(x, (vec){1, 0, 3, 2});       \
        x    ^= rc[round];                              \
                                                        \
        x    = ROTATE(x, 24);                           \
        y    = ROTATE(y,  9);                           \
        newz = x ^ (z << 1) ^ ((y & z) << 2);           \
        newy = y ^ x        ^ ((x | z) << 1);           \
        x    = z ^ y        ^ ((x & y) << 3);           \
        y    = newy;                                    \
        z    = newz;                                    \
                                                        \
        x    = ROTATE(x, 24);                           \
        y    = ROTATE(y,  9);                           \
        newz = x ^ (z << 1) ^ ((y & z) << 2);           \
        newy = y ^ x        ^ ((x | z) << 1);           \
        x    = z ^ y        ^ ((x & y) << 3);           \
        y    = newy;                                    \
        z    = newz;                                    \
                                                        \
        x    = vec_shuffle(x, (vec){2, 3, 0, 1});       \
                                                        \
        x    = ROTATE(x, 24);                           \
        y    = ROTATE(y,  9);                           \
        newz = x ^ (z << 1) ^ ((y & z) << 2);           \
        newy = y ^ x        ^ ((x | z) << 1);           \
        x    = z ^ y        ^ ((x & y) << 3);           \
        y    = newy;                                    \
        z    = newz;                                    \
                                                        \
    }


int crypto_stream(unsigned char *c, unsigned long long l, const unsigned char *n, const unsigned char *k) {

    long long j;
    unsigned char ncopy[16], kcopy[32];

    for (j = 0; j < 32; ++j) kcopy[j] = k[j];
    for (j = 0; j < 16; ++j) ncopy[j] = n[j];
    for (j = 0; j <  l; ++j) c[j] = 0;
    return crypto_stream_xor(c, c, l, ncopy, kcopy);
}

int crypto_stream_xor(unsigned char *c, const unsigned char *m, unsigned long long l, const unsigned char *n, const unsigned char *k) {

    long long round;
    vec newy, newz;
    vec x = unpack(n);
    vec y = unpack(k);
    vec z = unpack(k + 16);

    while (l >= 16) {
        GIMLI;
        pack(c, x ^ unpack(m));
        c += 16;
        m += 16;
        l -= 16;
    }

    if (l > 0) {
        unsigned char buf[16] = {0};
        long long i;
        GIMLI;
        for (i = 0; i < l; ++i) buf[i] = m[i];
        pack(buf, x ^ unpack(buf));
        for (i = 0; i < l; ++i) c[i] = buf[i];
    }

    return 0;
}
/* clang-format off */
