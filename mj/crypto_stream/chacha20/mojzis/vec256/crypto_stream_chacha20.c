/*
20200202
Jan Mojzis
Public domain.
*/

/*
SUPERCOP only !!!!!
*/

#include <stdint.h>
#include "crypto_stream.h"

#define BLOCKSIZE 512
typedef uint32_t vec32 __attribute__ ((vector_size (32)));
#define ROTATE(x, c) ((x) << (c)) ^ ((x) >> (32 - (c)))

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define UNPACK(x) *(uint32_t *)(x)
#else
#define UNPACK(x) \
        (uint32_t) ((x)[0])          \
    | (((uint32_t) ((x)[1])) << 8)   \
    | (((uint32_t) ((x)[2])) << 16)  \
    | (((uint32_t) ((x)[3])) << 24);
#endif

#define PACK(x, u, v) \
    (x)[0] = (u)[(v)]; (u)[(v)] >>= 8; \
    (x)[1] = (u)[(v)]; (u)[(v)] >>= 8; \
    (x)[2] = (u)[(v)]; (u)[(v)] >>= 8; \
    (x)[3] = (u)[(v)];

/* clang-format off */
#define vectorize(x) (vec32){*(uint32_t *)(x),*(uint32_t *)(x),*(uint32_t *)(x),*(uint32_t *)(x),*(uint32_t *)(x),*(uint32_t *)(x),*(uint32_t *)(x),*(uint32_t *)(x)}

static vec32 unpack32x4(const unsigned char *x) {

    vec32 r;

    r[0] = UNPACK(x);
#if BLOCKSIZE >= 256
    r[1] = UNPACK(x + 64);
    r[2] = UNPACK(x + 128);
    r[3] = UNPACK(x + 192);
#endif
#if BLOCKSIZE >= 512
    r[4] = UNPACK(x + 256);
    r[5] = UNPACK(x + 320);
    r[6] = UNPACK(x + 384);
    r[7] = UNPACK(x + 448);
#endif
    return r;
}

static void pack32x4(unsigned char *x, vec32 u) {

    PACK(x      , u, 0);
#if BLOCKSIZE >= 256
    PACK(x +  64, u, 1);
    PACK(x + 128, u, 2);
    PACK(x + 192, u, 3);
#endif
#if BLOCKSIZE >= 512
    PACK(x + 256, u, 4);
    PACK(x + 320, u, 5);
    PACK(x + 384, u, 6);
    PACK(x + 448, u, 7);
#endif
}

#define QUARTERROUND(a, b, c, d)                    \
    a += b; d = ROTATE(d ^ a, 16);                  \
    c += d; b = ROTATE(b ^ c, 12);                  \
    a += b; d = ROTATE(d ^ a,  8);                  \
    c += d; b = ROTATE(b ^ c,  7);

#define TWOROUNDS                                   \
    QUARTERROUND( x0, x4,  x8, x12)                 \
    QUARTERROUND( x1, x5,  x9, x13)                 \
    QUARTERROUND( x2, x6, x10, x14)                 \
    QUARTERROUND( x3, x7, x11, x15)                 \
    QUARTERROUND( x0, x5, x10, x15)                 \
    QUARTERROUND( x1, x6, x11, x12)                 \
    QUARTERROUND( x2, x7,  x8, x13)                 \
    QUARTERROUND( x3, x4,  x9, x14)

#define XORBLOCK(o, i)                              \
    x0  = s0;                                       \
    x1  = s1;                                       \
    x2  = s2;                                       \
    x3  = s3;                                       \
    x4  = k0;                                       \
    x5  = k1;                                       \
    x6  = k2;                                       \
    x7  = k3;                                       \
    x8  = k4;                                       \
    x9  = k5;                                       \
    x10 = k6;                                       \
    x11 = k7;                                       \
    x12 = n0;                                       \
    x13 = n1;                                       \
    x14 = n2;                                       \
    x15 = n3;                                       \
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
    pack32x4(o      ,  (x0 + s0) ^ unpack32x4(i     ));  \
    pack32x4(o +   4,  (x1 + s1) ^ unpack32x4(i +  4));  \
    pack32x4(o +   8,  (x2 + s2) ^ unpack32x4(i +  8));  \
    pack32x4(o +  12,  (x3 + s3) ^ unpack32x4(i + 12));  \
    pack32x4(o +  16,  (x4 + k0) ^ unpack32x4(i + 16));  \
    pack32x4(o +  20,  (x5 + k1) ^ unpack32x4(i + 20));  \
    pack32x4(o +  24,  (x6 + k2) ^ unpack32x4(i + 24));  \
    pack32x4(o +  28,  (x7 + k3) ^ unpack32x4(i + 28));  \
    pack32x4(o +  32,  (x8 + k4) ^ unpack32x4(i + 32));  \
    pack32x4(o +  36,  (x9 + k5) ^ unpack32x4(i + 36));  \
    pack32x4(o +  40, (x10 + k6) ^ unpack32x4(i + 40));  \
    pack32x4(o +  44, (x11 + k7) ^ unpack32x4(i + 44));  \
    pack32x4(o +  48, (x12 + n0) ^ unpack32x4(i + 48));  \
    pack32x4(o +  52, (x13 + n1) ^ unpack32x4(i + 52));  \
    pack32x4(o +  56, (x14 + n2) ^ unpack32x4(i + 56));  \
    pack32x4(o +  60, (x15 + n3) ^ unpack32x4(i + 60));

static const unsigned char sigma[16] = "expand 32-byte k";

int crypto_stream_xor(unsigned char *c, const unsigned char *m, unsigned long long l, const unsigned char *n, const unsigned char *k) {

    vec32 x0, x1, x2, x3, x4, x5, x6, x7;
    vec32 x8, x9, x10, x11, x12, x13, x14, x15;
    vec32 k0 = vectorize(k     );
    vec32 k1 = vectorize(k +  4);
    vec32 k2 = vectorize(k +  8);
    vec32 k3 = vectorize(k + 12);
    vec32 k4 = vectorize(k + 16);
    vec32 k5 = vectorize(k + 20);
    vec32 k6 = vectorize(k + 24);
    vec32 k7 = vectorize(k + 28);
    vec32 n0;
    vec32 n1;
    vec32 n2 = vectorize(n    );
    vec32 n3 = vectorize(n + 4);
    vec32 s0 = vectorize(sigma     );
    vec32 s1 = vectorize(sigma +  4);
    vec32 s2 = vectorize(sigma +  8);
    vec32 s3 = vectorize(sigma + 12);
    uint64_t u = 0;

    if (!l) return 0;

    n0[0] =   u; n1[0] = (u >> 32);
#if BLOCKSIZE >= 256
    n0[1] = ++u; n1[1] = (u >> 32);
    n0[2] = ++u; n1[2] = (u >> 32);
    n0[3] = ++u; n1[3] = (u >> 32);
#endif
#if BLOCKSIZE >= 512
    n0[4] = ++u; n1[4] = (u >> 32);
    n0[5] = ++u; n1[5] = (u >> 32);
    n0[6] = ++u; n1[6] = (u >> 32);
    n0[7] = ++u; n1[7] = (u >> 32);
#endif

    while (l >= BLOCKSIZE) {
        XORBLOCK(c, m);

        n0[0] = ++u; n1[0] = (u >> 32);
#if BLOCKSIZE >= 256
        n0[1] = ++u; n1[1] = (u >> 32);
        n0[2] = ++u; n1[2] = (u >> 32);
        n0[3] = ++u; n1[3] = (u >> 32);
#endif
#if BLOCKSIZE >= 512
        n0[4] = ++u; n1[4] = (u >> 32);
        n0[5] = ++u; n1[5] = (u >> 32);
        n0[6] = ++u; n1[6] = (u >> 32);
        n0[7] = ++u; n1[7] = (u >> 32);
#endif

        l -= BLOCKSIZE;
        c += BLOCKSIZE;
        m += BLOCKSIZE;
    }
    if (l) {
        unsigned char b[BLOCKSIZE] = {0};
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
