/*
20200202
Jan Mojzis
Public domain.
*/

#include <stdint.h>
#include "crypto_stream.h"

/* clang-format off */
static inline uint32_t unpack32(const unsigned char *x) {
    return
        (uint32_t) (x[0])                  \
    | (((uint32_t) (x[1])) << 8)           \
    | (((uint32_t) (x[2])) << 16)          \
    | (((uint32_t) (x[3])) << 24);
}

static inline void pack32(unsigned char *x, uint32_t u) {
    x[0] = u; u >>= 8;
    x[1] = u; u >>= 8;
    x[2] = u; u >>= 8;
    x[3] = u;
}

#define ROTATE(x, c) ((x) << (c)) ^ ((x) >> (32 - (c)))

#define TWOROUNDS                                   \
     x4 ^= ROTATE( x0+x12, 7);                      \
     x8 ^= ROTATE( x4+ x0, 9);                      \
    x12 ^= ROTATE( x8+ x4,13);                      \
     x0 ^= ROTATE(x12+ x8,18);                      \
     x9 ^= ROTATE( x5+ x1, 7);                      \
    x13 ^= ROTATE( x9+ x5, 9);                      \
     x1 ^= ROTATE(x13+ x9,13);                      \
     x5 ^= ROTATE( x1+x13,18);                      \
    x14 ^= ROTATE(x10+ x6, 7);                      \
     x2 ^= ROTATE(x14+x10, 9);                      \
     x6 ^= ROTATE( x2+x14,13);                      \
    x10 ^= ROTATE( x6+ x2,18);                      \
     x3 ^= ROTATE(x15+x11, 7);                      \
     x7 ^= ROTATE( x3+x15, 9);                      \
    x11 ^= ROTATE( x7+ x3,13);                      \
    x15 ^= ROTATE(x11+ x7,18);                      \
     x1 ^= ROTATE( x0+ x3, 7);                      \
     x2 ^= ROTATE( x1+ x0, 9);                      \
     x3 ^= ROTATE( x2+ x1,13);                      \
     x0 ^= ROTATE( x3+ x2,18);                      \
     x6 ^= ROTATE( x5+ x4, 7);                      \
     x7 ^= ROTATE( x6+ x5, 9);                      \
     x4 ^= ROTATE( x7+ x6,13);                      \
     x5 ^= ROTATE( x4+ x7,18);                      \
    x11 ^= ROTATE(x10+ x9, 7);                      \
     x8 ^= ROTATE(x11+x10, 9);                      \
     x9 ^= ROTATE( x8+x11,13);                      \
    x10 ^= ROTATE( x9+ x8,18);                      \
    x12 ^= ROTATE(x15+x14, 7);                      \
    x13 ^= ROTATE(x12+x15, 9);                      \
    x14 ^= ROTATE(x13+x12,13);                      \
    x15 ^= ROTATE(x14+x13,18);                      \


#define XORBLOCK(o, i)                              \
    x0  = s0;                                       \
    x1  = k0;                                       \
    x2  = k1;                                       \
    x3  = k2;                                       \
    x4  = k3;                                       \
    x5  = s1;                                       \
    x6  = n0;                                       \
    x7  = n1;                                       \
    x8  = n2;                                       \
    x9  = n3;                                       \
    x10 = s2;                                       \
    x11 = k4;                                       \
    x12 = k5;                                       \
    x13 = k6;                                       \
    x14 = k7;                                       \
    x15 = s3;                                       \
                                                    \
    TWOROUNDS /* round  1,  2 */                    \
    TWOROUNDS /* round  3,  4 */                    \
    TWOROUNDS /* round  5,  6 */                    \
    TWOROUNDS /* round  7,  8 */                    \
    TWOROUNDS /* round  9, 10 */                    \
    TWOROUNDS /* round 11, 12 */                    \
    TWOROUNDS /* round 13, 14 */                    \
    TWOROUNDS /* round 15, 16 */                    \
    TWOROUNDS /* round 17, 18 */                    \
    TWOROUNDS /* round 19, 20 */                    \
                                                    \
    pack32(o     ,  (x0 + s0) ^ unpack32(i     ));  \
    pack32(o +  4,  (x1 + k0) ^ unpack32(i +  4));  \
    pack32(o +  8,  (x2 + k1) ^ unpack32(i +  8));  \
    pack32(o + 12,  (x3 + k2) ^ unpack32(i + 12));  \
    pack32(o + 16,  (x4 + k3) ^ unpack32(i + 16));  \
    pack32(o + 20,  (x5 + s1) ^ unpack32(i + 20));  \
    pack32(o + 24,  (x6 + n0) ^ unpack32(i + 24));  \
    pack32(o + 28,  (x7 + n1) ^ unpack32(i + 28));  \
    pack32(o + 32,  (x8 + n2) ^ unpack32(i + 32));  \
    pack32(o + 36,  (x9 + n3) ^ unpack32(i + 36));  \
    pack32(o + 40, (x10 + s2) ^ unpack32(i + 40));  \
    pack32(o + 44, (x11 + k4) ^ unpack32(i + 44));  \
    pack32(o + 48, (x12 + k5) ^ unpack32(i + 48));  \
    pack32(o + 52, (x13 + k6) ^ unpack32(i + 52));  \
    pack32(o + 56, (x14 + k7) ^ unpack32(i + 56));  \
    pack32(o + 60, (x15 + s3) ^ unpack32(i + 60));

int crypto_stream_xor(unsigned char *c, const unsigned char *m, unsigned long long l, const unsigned char *n, const unsigned char *k) {

    register uint32_t x0, x1, x2, x3, x4, x5, x6, x7;
    register uint32_t x8, x9, x10, x11, x12, x13, x14, x15;
    uint32_t k0 = unpack32(k     );
    uint32_t k1 = unpack32(k +  4);
    uint32_t k2 = unpack32(k +  8);
    uint32_t k3 = unpack32(k + 12);
    uint32_t k4 = unpack32(k + 16);
    uint32_t k5 = unpack32(k + 20);
    uint32_t k6 = unpack32(k + 24);
    uint32_t k7 = unpack32(k + 28);
    uint32_t n0 = unpack32(n     );
    uint32_t n1 = unpack32(n +  4);
    uint32_t n2 = 0;
    uint32_t n3 = 0;
    uint32_t s0 = 0x61707865;
    uint32_t s1 = 0x3320646E;
    uint32_t s2 = 0x79622D32;
    uint32_t s3 = 0x6B206574;
    uint64_t u = 0;

    if (!l) return 0;

    while (l >= 64) {
        XORBLOCK(c, m);

        n2 = ++u;
        n3 = u >> 32;

        l -= 64;
        c += 64;
        m += 64;
    }
    if (l) {
        unsigned char b[64] = {0};
        long long j;

        for (j = 0; j < l; ++j) b[j] = m[j];
        XORBLOCK(b, b);
        for (j = 0; j < l; ++j) c[j] = b[j];
    }
    return 0;
}

int crypto_stream(unsigned char *c, unsigned long long l, const unsigned char *n, const unsigned char *k) {

    long long j;
    unsigned char ncopy[8], kcopy[32];

    for (j = 0; j < 32; ++j) kcopy[j] = k[j];
    for (j = 0; j <  8; ++j) ncopy[j] = n[j];
    for (j = 0; j <  l; ++j) c[j] = 0;
    return crypto_stream_xor(c, c, l, ncopy, kcopy);
}
/* clang-format on */
