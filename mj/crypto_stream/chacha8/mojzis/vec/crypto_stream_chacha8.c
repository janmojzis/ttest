/*
20200202
Jan Mojzis
Public domain.
*/

#include <stdint.h>
#include "crypto_stream.h"

/* clang-format off */

typedef uint32_t vec __attribute__ ((vector_size (32)));


#if BYTE_ORDER == LITTLE_ENDIAN
#define unpack32(x) (*(uint32_t *)(x))
#define pack32(x, u) *(uint32_t *)(x) = (u)
#elif BYTE_ORDER == BIG_ENDIAN
#define unpack32(x) __builtin_bswap32(*(uint32_t *)(x))
#define pack32(x, u) *(uint32_t *)(x) = __builtin_bswap32(u)
#else
#error
#endif

#ifdef __clang__
#define vec_shuffle __builtin_shufflevector
#define ROTATE(x, c) ((x) << (vec){(c), (c), (c), (c)}) ^ ((x) >> (32 - (vec){(c), (c), (c), (c)}))
#else
#define vec_shuffle __builtin_shuffle
#define ROTATE(x, c) ((x) << (c)) ^ ((x) >> (32 - (c)))
#endif
#define ROTV1(x)  (vec)vec_shuffle(x, (vec){1,2,3,0})
#define ROTV2(x)  (vec)vec_shuffle(x, (vec){2,3,0,1})
#define ROTV3(x)  (vec)vec_shuffle(x, (vec){3,0,1,2})

#if 0
#define unpack32x4(x) (*(vec *)(x))
#define pack32x4(x, u) *(vec *)(x) = (u)
#else
static vec unpack32x4(const unsigned char *x) {

    vec r;

    r[0] = unpack32(x     );
    r[1] = unpack32(x +  4);
    r[2] = unpack32(x +  8);
    r[3] = unpack32(x + 12);
    return r;
}

static void pack32x4(unsigned char *x, vec u) {

    pack32(x     , u[0]);
    pack32(x +  4, u[1]);
    pack32(x +  8, u[2]);
    pack32(x + 12, u[3]);
}
#endif

#define TWOROUNDS(a, b, c, d)                       \
    a += b; d ^= a; d = ROTATE(d, 16);              \
    c += d; b ^= c; b = ROTATE(b, 12);              \
    a += b; d ^= a; d = ROTATE(d, 8);               \
    c += d; b ^= c; b = ROTATE(b, 7);               \
    b = ROTV1(b); c = ROTV2(c);  d = ROTV3(d);      \
    a += b; d ^= a; d = ROTATE(d, 16);              \
    c += d; b ^= c; b = ROTATE(b, 12);              \
    a += b; d ^= a; d = ROTATE(d, 8);               \
    c += d; b ^= c; b = ROTATE(b, 7);               \
    b = ROTV3(b); c = ROTV2(c); d = ROTV1(d);


#define BLOCK(a, b, c, d, n)                        \
    a = s0;                                         \
    b = k0;                                         \
    c = k1;                                         \
    d = n;                                          \
                                                    \
    TWOROUNDS(a, b, c, d) /* round  1,  2 */        \
    TWOROUNDS(a, b, c, d) /* round  3,  4 */        \
    TWOROUNDS(a, b, c, d) /* round  5,  6 */        \
    TWOROUNDS(a, b, c, d) /* round  7,  8 */        \
                                                    \
    a += s0;                                        \
    b += k0;                                        \
    c += k1;                                        \
    d += n;                                         \
                                                    

#define XOR(o, i, a, b, c, d)                       \
    pack32x4(o     ,  a ^ unpack32x4(i     ));      \
    pack32x4(o + 16,  b ^ unpack32x4(i + 16));      \
    pack32x4(o + 32,  c ^ unpack32x4(i + 32));      \
    pack32x4(o + 48,  d ^ unpack32x4(i + 48));

static const unsigned char s[16] = "expand 32-byte k";

int crypto_stream_xor(unsigned char *c, const unsigned char *m, unsigned long long l, const unsigned char *n, const unsigned char *k) {

    vec x0, x1, x2, x3;
    vec x4, x5, x6, x7;
    vec x8, x9, x10, x11;
    uint64_t u = 0;
    vec s0 = unpack32x4(s);
    vec k0 = unpack32x4(k);
    vec k1 = unpack32x4(k + 16);
    vec n0, n1, n2;
    n0[2] = n1[2] = n2[2] = unpack32(n    );
    n0[3] = n1[3] = n2[3] = unpack32(n + 4);

    if (!l) return 0;

    while (l >= 192) {
        n0[0] = u; n0[1] = (u >> 32); ++u;
        n1[0] = u; n1[1] = (u >> 32); ++u;
        n2[0] = u; n2[1] = (u >> 32); ++u;
        BLOCK(x0, x1, x2,  x3,  n0);
        BLOCK(x4, x5, x6,  x7,  n1);
        BLOCK(x8, x9, x10, x11, n2);
        XOR(c     , m     , x0, x1,  x2,  x3);
        XOR(c +  64, m +  64, x4, x5,  x6,  x7);
        XOR(c + 128, m + 128, x8, x9, x10, x11);

        l -= 192;
        c += 192;
        m += 192;
    }
    while (l >= 128) {
        n0[0] = u; n0[1] = (u >> 32); ++u;
        n1[0] = u; n1[1] = (u >> 32); ++u;
        BLOCK(x0, x1, x2, x3, n0);
        BLOCK(x4, x5, x6, x7, n1);
        XOR(c     , m     , x0, x1, x2, x3);
        XOR(c + 64, m + 64, x4, x5, x6, x7);

        l -= 128;
        c += 128;
        m += 128;
    }
    while (l >= 64) {
        n0[0] = u; n0[1] = (u >> 32); ++u;
        BLOCK(x0, x1, x2, x3, n0);
        XOR(c, m, x0, x1, x2, x3);

        l -= 64;
        c += 64;
        m += 64;
    }
    if (l) {
        unsigned char b[64] = {0};
        long long j;

        for (j = 0; j < l; ++j) b[j] = m[j];
        n0[0] = u; n0[1] = (u >> 32); ++u;
        BLOCK(x0, x1, x2, x3, n0);
        XOR(b, b, x0, x1, x2, x3);
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
