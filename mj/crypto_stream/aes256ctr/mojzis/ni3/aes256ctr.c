#include <wmmintrin.h>
#include <tmmintrin.h>
#include "crypto_stream.h"

#define EXPAND1(r)                                              \
  temp1 = _mm_aeskeygenassist_si128(temp2, (r));                \
  temp1 = _mm_shuffle_epi32(temp1, _MM_SHUFFLE(3, 3, 3, 3));    \
  temp0 = _mm_xor_si128(temp0, _mm_slli_si128(temp0, 4));       \
  temp0 = _mm_xor_si128(temp0, _mm_slli_si128(temp0, 8));       \
  temp0 = _mm_xor_si128(temp0, temp1)

#define EXPAND2(r)                                              \
  temp1 = _mm_aeskeygenassist_si128(temp0, (r));                \
  temp1 = _mm_shuffle_epi32(temp1, _MM_SHUFFLE(2, 2, 2, 2));    \
  temp2 = _mm_xor_si128(temp2, _mm_slli_si128(temp2, 4));       \
  temp2 = _mm_xor_si128(temp2, _mm_slli_si128(temp2, 8));       \
  temp2 = _mm_xor_si128(temp2, temp1)

#define BLOCKS(a, b, c)                 \
    temp0 = K0;                         \
    temp2 = K1;                         \
    a = _mm_xor_si128(a, temp0);        \
    b = _mm_xor_si128(b, temp0);        \
    c = _mm_xor_si128(c, temp0);        \
    a = _mm_aesenc_si128(a, temp2);     \
    b = _mm_aesenc_si128(b, temp2);     \
    c = _mm_aesenc_si128(c, temp2);     \
    EXPAND1(0x01);                      \
    a = _mm_aesenc_si128(a, temp0);     \
    b = _mm_aesenc_si128(b, temp0);     \
    c = _mm_aesenc_si128(c, temp0);     \
    EXPAND2(0x01);                      \
    a = _mm_aesenc_si128(a, temp2);     \
    b = _mm_aesenc_si128(b, temp2);     \
    c = _mm_aesenc_si128(c, temp2);     \
    EXPAND1(0x02);                      \
    a = _mm_aesenc_si128(a, temp0);     \
    b = _mm_aesenc_si128(b, temp0);     \
    c = _mm_aesenc_si128(c, temp0);     \
    EXPAND2(0x02);                      \
    a = _mm_aesenc_si128(a, temp2);     \
    b = _mm_aesenc_si128(b, temp2);     \
    c = _mm_aesenc_si128(c, temp2);     \
    EXPAND1(0x04);                      \
    a = _mm_aesenc_si128(a, temp0);     \
    b = _mm_aesenc_si128(b, temp0);     \
    c = _mm_aesenc_si128(c, temp0);     \
    EXPAND2(0x04);                      \
    a = _mm_aesenc_si128(a, temp2);     \
    b = _mm_aesenc_si128(b, temp2);     \
    c = _mm_aesenc_si128(c, temp2);     \
    EXPAND1(0x08);                      \
    a = _mm_aesenc_si128(a, temp0);     \
    b = _mm_aesenc_si128(b, temp0);     \
    c = _mm_aesenc_si128(c, temp0);     \
    EXPAND2(0x08);                      \
    a = _mm_aesenc_si128(a, temp2);     \
    b = _mm_aesenc_si128(b, temp2);     \
    c = _mm_aesenc_si128(c, temp2);     \
    EXPAND1(0x10);                      \
    a = _mm_aesenc_si128(a, temp0);     \
    b = _mm_aesenc_si128(b, temp0);     \
    c = _mm_aesenc_si128(c, temp0);     \
    EXPAND2(0x10);                      \
    a = _mm_aesenc_si128(a, temp2);     \
    b = _mm_aesenc_si128(b, temp2);     \
    c = _mm_aesenc_si128(c, temp2);     \
    EXPAND1(0x20);                      \
    a = _mm_aesenc_si128(a, temp0);     \
    b = _mm_aesenc_si128(b, temp0);     \
    c = _mm_aesenc_si128(c, temp0);     \
    EXPAND2(0x20);                      \
    a = _mm_aesenc_si128(a, temp2);     \
    b = _mm_aesenc_si128(b, temp2);     \
    c = _mm_aesenc_si128(c, temp2);     \
    EXPAND1(0x40);                      \
    a = _mm_aesenclast_si128(a, temp0); \
    b = _mm_aesenclast_si128(b, temp0); \
    c = _mm_aesenclast_si128(c, temp0);

#define XOR(x, c, m) _mm_storeu_si128((__m128i *)(c), (x) ^ _mm_loadu_si128((const __m128i *)(m)))
#define NONCELOAD(n) _mm_shuffle_epi8(_mm_load_si128((const __m128i *)(n)), _mm_set_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15))

typedef unsigned uint128_t __attribute__((mode(TI)));

int crypto_stream_xor(unsigned char *c, const unsigned char *m, unsigned long long l, const unsigned char *n, const unsigned char *k) {

    register __m128i temp0, temp1, temp2, X0, X1, X2, K0, K1;
    __attribute__((aligned(16))) uint128_t noncele;

    if (!l) return 0;

    K0 = _mm_loadu_si128((const __m128i *)(k     ));
    K1 = _mm_loadu_si128((const __m128i *)(k + 16));
    _mm_store_si128((__m128i *)&noncele, NONCELOAD(n));

    while (l >= 48) {
        
        X0 = NONCELOAD(&noncele); ++noncele;
        X1 = NONCELOAD(&noncele); ++noncele;
        X2 = NONCELOAD(&noncele); ++noncele;
        BLOCKS(X0, X1, X2);
        XOR(X0, c     , m     );
        XOR(X1, c + 16, m + 16);
        XOR(X2, c + 32, m + 32);

        l -= 48;
        c += 48;
        m += 48;
    }
    if (l) {
        __attribute__((aligned(16))) unsigned char b[48] = {0};
        long long j;

        for (j = 0; j < l; ++j) b[j] = m[j];
        X0 = NONCELOAD(&noncele); ++noncele;
        X1 = NONCELOAD(&noncele); ++noncele;
        X2 = NONCELOAD(&noncele);
        BLOCKS(X0, X1, X2);
        XOR(X0, b     , b     );
        XOR(X1, b + 16, b + 16);
        XOR(X2, b + 32, b + 32);
        for (j = 0; j < l; ++j) c[j] = b[j];
    }
    return 0;
}

int crypto_stream(unsigned char *c, unsigned long long l, const unsigned char *n, const unsigned char *k) {

    long long j;
    unsigned char noncele[16], kcopy[32];

    for (j = 0; j < 32; ++j) kcopy[j] = k[j];
    for (j = 0; j < 16; ++j) noncele[j] = n[j];
    for (j = 0; j <  l; ++j) c[j] = 0;
    return crypto_stream_xor(c, c, l, noncele, kcopy);
}
