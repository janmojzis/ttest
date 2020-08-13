/*
20200202
Jan Mojzis
Public domain.
*/

#include <stdint.h>
#include "crypto_stream.h"

/* clang-format off */

typedef uint32_t vec32 __attribute__ ((vector_size (16)));

/* platform optimization */
#if __SSE2__
#define BLOCKS 3
#elif __ARM_NEON__
#define BLOCKS 2
#else
#define BLOCKS 1
#endif

/* endianness */
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define vec32_beswap(x) (x)
#else
vec32 vec32_beswap(vec32 u) {
    vec r;
    r[0] = __builtin_bswap32(u[0]);
    r[1] = __builtin_bswap32(u[1]);
    r[2] = __builtin_bswap32(u[2]);
    r[3] = __builtin_bswap32(u[3]);
    return r;
}
#endif

/* compiler */
#ifdef __clang__
#define vec32_shuffle __builtin_shufflevector
#else
#define vec32_shuffle __builtin_shuffle
#endif
#define ROTATE(x, c) ((x) << (c)) ^ ((x) >> (32 - (c)))
#define SHUFFLE1(x)  (vec32)vec32_shuffle(x, (vec32){1,2,3,0})
#define SHUFFLE2(x)  (vec32)vec32_shuffle(x, (vec32){2,3,0,1})
#define SHUFFLE3(x)  (vec32)vec32_shuffle(x, (vec32){3,0,1,2})

#define TWOROUNDS(a, b, c, d)                           \
    a += b; d ^= a; d = ROTATE(d, 16);                  \
    c += d; b ^= c; b = ROTATE(b, 12);                  \
    a += b; d ^= a; d = ROTATE(d, 8);                   \
    c += d; b ^= c; b = ROTATE(b, 7);                   \
    b = SHUFFLE1(b); c = SHUFFLE2(c);  d = SHUFFLE3(d); \
    a += b; d ^= a; d = ROTATE(d, 16);                  \
    c += d; b ^= c; b = ROTATE(b, 12);                  \
    a += b; d ^= a; d = ROTATE(d, 8);                   \
    c += d; b ^= c; b = ROTATE(b, 7);                   \
    b = SHUFFLE3(b); c = SHUFFLE2(c); d = SHUFFLE1(d);

#define BLOCK_SETUP(a, b, c, d, _s0, _k0, _k1, _n0, x)  \
    register vec32 (a) = (_s0);                         \
    register vec32 (b) = (_k0);                         \
    register vec32 (c) = (_k1);                         \
    register vec32 (d) = (_n0);                         \
    (d) += (vec32){(x), (x) >> 32, 0, 0};               \

#define BLOCK(a, b, c, d)                               \
    TWOROUNDS(a, b, c, d) /* round  1,  2 */            \
    TWOROUNDS(a, b, c, d) /* round  3,  4 */            \
    TWOROUNDS(a, b, c, d) /* round  5,  6 */            \
    TWOROUNDS(a, b, c, d) /* round  7,  8 */            \
    TWOROUNDS(a, b, c, d) /* round  9, 10 */            \
    TWOROUNDS(a, b, c, d) /* round 10, 12 */            \
    TWOROUNDS(a, b, c, d) /* round 13, 14 */            \
    TWOROUNDS(a, b, c, d) /* round 15, 16 */            \
    TWOROUNDS(a, b, c, d) /* round 17, 18 */            \
    TWOROUNDS(a, b, c, d) /* round 19, 20 */

#define BLOCK_FINALIZE(a, b, c, d, _s, _k0, _k1, _n, x) \
    (a) += (_s);                                        \
    (b) += (_k0);                                       \
    (c) += (_k1);                                       \
    (d) += (_n) + (vec32){(x), (x) >> 32, 0, 0};
                                                    
#define BLOCK_XOR(o, i, a, b, c, d)                     \
    (a) = vec32_beswap(a);                              \
    (b) = vec32_beswap(b);                              \
    (c) = vec32_beswap(c);                              \
    (d) = vec32_beswap(d);                              \
    *(vec32 *)((o)     ) = (a) ^ *(vec32 *)((i)     );  \
    *(vec32 *)((o) + 16) = (b) ^ *(vec32 *)((i) + 16);  \
    *(vec32 *)((o) + 32) = (c) ^ *(vec32 *)((i) + 32);  \
    *(vec32 *)((o) + 48) = (d) ^ *(vec32 *)((i) + 48);

static const unsigned char s[16] = "expand 32-byte k";

int crypto_stream_xor(unsigned char *c, const unsigned char *m, unsigned long long l, const unsigned char *n, const unsigned char *k) {

    vec32 s0 = vec32_beswap(*(vec32 *)(s));
    vec32 k0 = vec32_beswap(*(vec32 *)(k));
    vec32 k1 = vec32_beswap(*(vec32 *)(k + 16));
    vec32 n0;
    uint64_t u = 0;

    if (!l) return 0;

    {
        unsigned char nonce[16] = {0};
        long long j;
        for (j = 0; j < 8; ++j) nonce[j + 8] = n[j];
        n0 = vec32_beswap(*(vec32 *)(nonce));
    }

#if BLOCKS >= 3
    while (l >= 192) {
        BLOCK_SETUP(x0, x1,  x2,  x3, s0, k0, k1, n0, u);
        BLOCK_SETUP(x4, x5,  x6,  x7, s0, k0, k1, n0, u + 1);
        BLOCK_SETUP(x8, x9, x10, x11, s0, k0, k1, n0, u + 2);
        BLOCK(x0, x1, x2, x3);
        BLOCK(x4, x5, x6, x7);
        BLOCK(x8, x9, x10, x11);
        BLOCK_FINALIZE(x0, x1,  x2,  x3, s0, k0, k1, n0, u);
        BLOCK_FINALIZE(x4, x5,  x6,  x7, s0, k0, k1, n0, u + 1);
        BLOCK_FINALIZE(x8, x9, x10, x11, s0, k0, k1, n0, u + 2);
        BLOCK_XOR(c      , m      , x0, x1, x2, x3);
        BLOCK_XOR(c +  64, m +  64, x4, x5, x6, x7);
        BLOCK_XOR(c + 128, m + 128, x8, x9, x10, x11);
        u += 3;
        l -= 192;
        c += 192;
        m += 192;
    }
#endif
#if BLOCKS >= 2
    while (l >= 128) {
        BLOCK_SETUP(x0, x1,  x2,  x3, s0, k0, k1, n0, u);
        BLOCK_SETUP(x4, x5,  x6,  x7, s0, k0, k1, n0, u + 1);
        BLOCK(x0, x1, x2, x3);
        BLOCK(x4, x5, x6, x7);
        BLOCK_FINALIZE(x0, x1,  x2,  x3, s0, k0, k1, n0, u);
        BLOCK_FINALIZE(x4, x5,  x6,  x7, s0, k0, k1, n0, u + 1);
        BLOCK_XOR(c     , m     , x0, x1, x2, x3);
        BLOCK_XOR(c + 64, m + 64, x4, x5, x6, x7);
        u += 2;
        l -= 128;
        c += 128;
        m += 128;
    }
#endif
    while (l >= 64) {
        BLOCK_SETUP(x0, x1,  x2,  x3, s0, k0, k1, n0, u);
        BLOCK(x0, x1, x2, x3);
        BLOCK_FINALIZE(x0, x1,  x2,  x3, s0, k0, k1, n0, u);
        BLOCK_XOR(c, m, x0, x1, x2, x3);
        u += 1;
        l -= 64;
        c += 64;
        m += 64;
    }
    if (l) {
        unsigned char b[64] = {0};
        long long j;
        BLOCK_SETUP(x0, x1,  x2,  x3, s0, k0, k1, n0, u);
        BLOCK(x0, x1, x2, x3);
        BLOCK_FINALIZE(x0, x1,  x2,  x3, s0, k0, k1, n0, u);
        for (j = 0; j < l; ++j) b[j] = m[j];
        BLOCK_XOR(b, b, x0, x1, x2, x3);
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
