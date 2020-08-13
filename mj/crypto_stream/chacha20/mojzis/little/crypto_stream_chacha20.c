/*
20200202
Jan Mojzis
Public domain.
*/

/* clang-format off */
#include <stdint.h>
#include "crypto_stream.h"

/* compiler hacks */
#ifdef __clang__
#define vec32_shuffle __builtin_shufflevector
#else
#define vec32_shuffle __builtin_shuffle
#endif

/* platform optimization */
#if defined(__SSE2__)
#define PARALLEL 3
#elif defined(__ARM_NEON__)
#define PARALLEL 2
#else
#define PARALLEL 1
#endif

#if defined(__AVX2__)
#define BLOCKS 2
#else
#define BLOCKS 1
#endif

/* portable vector */
typedef uint32_t vec32 __attribute__ ((vector_size (BLOCKS * 16)));

/* endianness */
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define _le(x) (x)
#else
#define _le(x) __builtin_bswap(x)
#endif

#if BLOCKS == 2
#define SHUFFLE1(x) (vec32) vec32_shuffle(x, (vec32) { 1, 2, 3, 0, 5, 6, 7, 4 })
#define SHUFFLE2(x) (vec32) vec32_shuffle(x, (vec32) { 2, 3, 0, 1, 6, 7, 4, 5 })
#define SHUFFLE3(x) (vec32) vec32_shuffle(x, (vec32) { 3, 0, 1, 2, 7, 4, 5, 6 })
#define NONCE(n0, x) ((vec32) { (x), (x) >> 32, 0, 0, (x) + 1, ((x) + 1) >> 32, 0, 0 } + n0);
#define vec32_EXPAND(a, b, c, d) (vec32) { _le(a), _le(b), _le(c), _le(d), _le(a), _le(b), _le(c), _le(d) }
#define BLOCK_REORDER(a, b, c, d)                                                                               \
    {                                                                                                           \
        vec32 aa = { _le(a[0]), _le(a[1]), _le(a[2]), _le(a[3]), _le(b[0]), _le(b[1]), _le(b[2]), _le(b[3]) };  \
        vec32 bb = { _le(c[0]), _le(c[1]), _le(c[2]), _le(c[3]), _le(d[0]), _le(d[1]), _le(d[2]), _le(d[3]) };  \
        vec32 cc = { _le(a[4]), _le(a[5]), _le(a[6]), _le(a[7]), _le(b[4]), _le(b[5]), _le(b[6]), _le(b[7]) };  \
        vec32 dd = { _le(c[4]), _le(c[5]), _le(c[6]), _le(c[7]), _le(d[4]), _le(d[5]), _le(d[6]), _le(d[7]) };  \
        a = aa; b = bb; c = cc; d = dd;                                                                         \
    }
#else
#define SHUFFLE1(x) (vec32)vec32_shuffle(x, (vec32) { 1, 2, 3, 0 })
#define SHUFFLE2(x) (vec32)vec32_shuffle(x, (vec32) { 2, 3, 0, 1 })
#define SHUFFLE3(x) (vec32)vec32_shuffle(x, (vec32) { 3, 0, 1, 2 })
#define NONCE(n0, x) ((vec32) { (x), (x) >> 32, 0, 0 } + n0);
#define vec32_EXPAND(a, b, c, d) (vec32) { _le(a), _le(b), _le(c), _le(d) }
#define BLOCK_REORDER(a, b, c, d)                                   \
    {                                                               \
        vec32 aa = { _le(a[0]), _le(a[1]), _le(a[2]), _le(a[3]) };  \
        vec32 bb = { _le(b[0]), _le(b[1]), _le(b[2]), _le(b[3]) };  \
        vec32 cc = { _le(c[0]), _le(c[1]), _le(c[2]), _le(c[3]) };  \
        vec32 dd = { _le(d[0]), _le(d[1]), _le(d[2]), _le(d[3]) };  \
        a = aa; b = bb; c = cc; d = dd;                             \
    }
#endif


/* chacha */

#define ROTATE(x, c) ((x) << (c)) ^ ((x) >> (32 - (c)))

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

    
#define BLOCK_SETUP(a, b, c, d, _s0, _k0, _k1, _n0, x)  \
    register vec32 (a) = (_s0);                         \
    register vec32 (b) = (_k0);                         \
    register vec32 (c) = (_k1);                         \
    register vec32 (d) = NONCE(_n0, x);

#define BLOCK_FINALIZE(a, b, c, d, _s, _k0, _k1, _n, x) \
    (a) += (_s);                                        \
    (b) += (_k0);                                       \
    (c) += (_k1);                                       \
    (d) += NONCE(_n, x);

#define BLOCK_XOR(o, i, a, b, c, d)                                     \
    BLOCK_REORDER(a, b, c, d)                                           \
    *(vec32 *)((o)              ) = (a) ^ *(vec32 *)((i)              );\
    *(vec32 *)((o) + 16 * BLOCKS) = (b) ^ *(vec32 *)((i) + 16 * BLOCKS);\
    *(vec32 *)((o) + 32 * BLOCKS) = (c) ^ *(vec32 *)((i) + 32 * BLOCKS);\
    *(vec32 *)((o) + 48 * BLOCKS) = (d) ^ *(vec32 *)((i) + 48 * BLOCKS);

static __attribute__((aligned(16))) const unsigned char sx[16] = "expand 32-byte k";

int crypto_stream_xor(unsigned char *c, const unsigned char *m, unsigned long long l, const unsigned char *nx, const unsigned char *kx) {

    uint64_t u = 0;
    uint32_t *k = (uint32_t *)kx;
    uint32_t *s = (uint32_t *)sx;
    uint32_t *n = (uint32_t *)nx;
    vec32 n0 = vec32_EXPAND(   0,    0, n[0], n[1]);
    vec32 k0 = vec32_EXPAND(k[0], k[1], k[2], k[3]);
    vec32 k1 = vec32_EXPAND(k[4], k[5], k[6], k[7]);
    vec32 s0 = vec32_EXPAND(s[0], s[1], s[2], s[3]);

    if (!l) return 0;

#if PARALLEL >= 3
    while (l >= 3 * BLOCKS * 64) {
        BLOCK_SETUP(x0, x1,  x2,  x3, s0, k0, k1, n0, u);
        BLOCK_SETUP(x4, x5,  x6,  x7, s0, k0, k1, n0, u + BLOCKS);
        BLOCK_SETUP(x8, x9, x10, x11, s0, k0, k1, n0, u + 2 * BLOCKS);
        BLOCK(x0, x1, x2, x3);
        BLOCK(x4, x5, x6, x7);
        BLOCK(x8, x9, x10, x11);
        BLOCK_FINALIZE(x0, x1,  x2,  x3, s0, k0, k1, n0, u);
        BLOCK_FINALIZE(x4, x5,  x6,  x7, s0, k0, k1, n0, u + BLOCKS);
        BLOCK_FINALIZE(x8, x9, x10, x11, s0, k0, k1, n0, u + 2 * BLOCKS);
        BLOCK_XOR(c                  , m                  , x0, x1,  x2,  x3);
        BLOCK_XOR(c +     BLOCKS * 64, m +     BLOCKS * 64, x4, x5,  x6,  x7);
        BLOCK_XOR(c + 2 * BLOCKS * 64, m + 2 * BLOCKS * 64, x8, x9, x10, x11);
        u += 3 * BLOCKS;
        l -= 3 * BLOCKS * 64;
        c += 3 * BLOCKS * 64;
        m += 3 * BLOCKS * 64;
    }
#endif
#if PARALLEL >= 2
    while (l >= 2 * BLOCKS * 64) {
        BLOCK_SETUP(x0, x1,  x2,  x3, s0, k0, k1, n0, u);
        BLOCK_SETUP(x4, x5,  x6,  x7, s0, k0, k1, n0, u + BLOCKS);
        BLOCK(x0, x1, x2, x3);
        BLOCK(x4, x5, x6, x7);
        BLOCK_FINALIZE(x0, x1,  x2,  x3, s0, k0, k1, n0, u);
        BLOCK_FINALIZE(x4, x5,  x6,  x7, s0, k0, k1, n0, u + BLOCKS);
        BLOCK_XOR(c              , m              , x0, x1, x2, x3);
        BLOCK_XOR(c + BLOCKS * 64, m + BLOCKS * 64, x4, x5, x6, x7);
        u += 2 * BLOCKS;
        l -= 2 * BLOCKS * 64;
        c += 2 * BLOCKS * 64;
        m += 2 * BLOCKS * 64;
    }
#endif
    while (l >= BLOCKS * 64) {
        BLOCK_SETUP(x0, x1,  x2,  x3, s0, k0, k1, n0, u);
        BLOCK(x0, x1, x2, x3);
        BLOCK_FINALIZE(x0, x1,  x2,  x3, s0, k0, k1, n0, u);
        BLOCK_XOR(c, m, x0, x1, x2, x3);
        u += BLOCKS;
        l -= BLOCKS * 64;
        c += BLOCKS * 64;
        m += BLOCKS * 64;
    }
    if (l) {
        __attribute__((aligned(16))) unsigned char b[BLOCKS * 64] = {0};
        vec32 *bb = (vec32 *)b;
        long long j;
        BLOCK_SETUP(x0, x1,  x2,  x3, s0, k0, k1, n0, u);
        BLOCK(x0, x1, x2, x3);
        BLOCK_FINALIZE(x0, x1,  x2,  x3, s0, k0, k1, n0, u);
        for (j = 0; j < l; ++j) b[j] = m[j];
        BLOCK_XOR(bb, bb, x0, x1, x2, x3);
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
