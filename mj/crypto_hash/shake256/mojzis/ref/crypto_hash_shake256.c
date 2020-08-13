/*
20200202
Jan Mojzis
Public domain.
*/

#include <stdint.h>
#include "crypto_hash.h"

/* clang-format off */
static inline uint64_t unpack64(const unsigned char *x) {
    return
        (uint64_t) (x[0])                  \
    | (((uint64_t) (x[1])) << 8)           \
    | (((uint64_t) (x[2])) << 16)          \
    | (((uint64_t) (x[3])) << 24)          \
    | (((uint64_t) (x[4])) << 32)          \
    | (((uint64_t) (x[5])) << 40)          \
    | (((uint64_t) (x[6])) << 48)          \
    | (((uint64_t) (x[7])) << 56);
}

static inline void pack64(unsigned char *x, uint64_t u) {
    x[0] = u; u >>= 8;
    x[1] = u; u >>= 8;
    x[2] = u; u >>= 8;
    x[3] = u; u >>= 8;
    x[4] = u; u >>= 8;
    x[5] = u; u >>= 8;
    x[6] = u; u >>= 8;
    x[7] = u;
}

#define ROTATE(x, c) (((x) << (c)) ^ ((x) >> (64 - (c))))

static const uint64_t rc[24] = {
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
    0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008
};

static void keccak(uint64_t s[25]) {

    long long i;
    uint64_t t, b[5];

    for (i = 0; i < 24; ++i) {

        /*
        Theta, unrolled:
        for (i = 0; i < 5; ++i) {
            b[i] = s[i] ^ s[i + 5] ^ s[i + 10] ^ s[i + 15] ^ s[i + 20];
        }
        for (i = 0; i < 5; ++i) {
            t = b[(i + 4) % 5] ^ ROTATE(b[(i + 1) % 5], 1);
            for (j = 0; j < 25; j += 5) s[j + i] ^= t;
        }
        */

        b[0] = s[0] ^ s[5] ^ s[10] ^ s[15] ^ s[20];
        b[1] = s[1] ^ s[6] ^ s[11] ^ s[16] ^ s[21];
        b[2] = s[2] ^ s[7] ^ s[12] ^ s[17] ^ s[22];
        b[3] = s[3] ^ s[8] ^ s[13] ^ s[18] ^ s[23];
        b[4] = s[4] ^ s[9] ^ s[14] ^ s[19] ^ s[24];
        t = b[4] ^ ROTATE(b[1], 1);
        s[ 0] ^= t;
        s[ 5] ^= t;
        s[10] ^= t;
        s[15] ^= t;
        s[20] ^= t;
        t = b[0] ^ ROTATE(b[2], 1);
        s[ 1] ^= t;
        s[ 6] ^= t;
        s[11] ^= t;
        s[16] ^= t;
        s[21] ^= t;
        t = b[1] ^ ROTATE(b[3], 1);
        s[ 2] ^= t;
        s[ 7] ^= t;
        s[12] ^= t;
        s[17] ^= t;
        s[22] ^= t;
        t = b[2] ^ ROTATE(b[4], 1);
        s[ 3] ^= t;
        s[ 8] ^= t;
        s[13] ^= t;
        s[18] ^= t;
        s[23] ^= t;
        t = b[3] ^ ROTATE(b[0], 1);
        s[ 4] ^= t;
        s[ 9] ^= t;
        s[14] ^= t;
        s[19] ^= t;
        s[24] ^= t;

        /* Rho and Pi: */
        t = s[1];
        b[0] = s[10]; s[10] = ROTATE(t,  1); t = b[0];
        b[0] = s[ 7]; s[ 7] = ROTATE(t,  3); t = b[0];
        b[0] = s[11]; s[11] = ROTATE(t,  6); t = b[0];
        b[0] = s[17]; s[17] = ROTATE(t, 10); t = b[0];
        b[0] = s[18]; s[18] = ROTATE(t, 15); t = b[0];
        b[0] = s[ 3]; s[ 3] = ROTATE(t, 21); t = b[0];
        b[0] = s[ 5]; s[ 5] = ROTATE(t, 28); t = b[0];
        b[0] = s[16]; s[16] = ROTATE(t, 36); t = b[0];
        b[0] = s[ 8]; s[ 8] = ROTATE(t, 45); t = b[0];
        b[0] = s[21]; s[21] = ROTATE(t, 55); t = b[0];
        b[0] = s[24]; s[24] = ROTATE(t,  2); t = b[0];
        b[0] = s[ 4]; s[ 4] = ROTATE(t, 14); t = b[0];
        b[0] = s[15]; s[15] = ROTATE(t, 27); t = b[0];
        b[0] = s[23]; s[23] = ROTATE(t, 41); t = b[0];
        b[0] = s[19]; s[19] = ROTATE(t, 56); t = b[0];
        b[0] = s[13]; s[13] = ROTATE(t,  8); t = b[0];
        b[0] = s[12]; s[12] = ROTATE(t, 25); t = b[0];
        b[0] = s[ 2]; s[ 2] = ROTATE(t, 43); t = b[0];
        b[0] = s[20]; s[20] = ROTATE(t, 62); t = b[0];
        b[0] = s[14]; s[14] = ROTATE(t, 18); t = b[0];
        b[0] = s[22]; s[22] = ROTATE(t, 39); t = b[0];
        b[0] = s[ 9]; s[ 9] = ROTATE(t, 61); t = b[0];
        b[0] = s[ 6]; s[ 6] = ROTATE(t, 20); t = b[0];
        b[0] = s[ 1]; s[ 1] = ROTATE(t, 44); t = b[0];

       /*
       Chi, unrolled:
       for (j = 0; j < 25; j += 5) {
            for (i = 0; i < 5; ++i) b[i] = s[j + i];
            for (i = 0; i < 5; ++i) s[j + i] ^= (~b[(i + 1) % 5]) & b[(i + 2) % 5];
        }
        */
        b[0] = s[0];
        b[1] = s[1];
        b[2] = s[2];
        b[3] = s[3];
        b[4] = s[4];
        s[0] ^= (~b[1]) & b[2];
        s[1] ^= (~b[2]) & b[3];
        s[2] ^= (~b[3]) & b[4];
        s[3] ^= (~b[4]) & b[0];
        s[4] ^= (~b[0]) & b[1];
        b[0] = s[5];
        b[1] = s[6];
        b[2] = s[7];
        b[3] = s[8];
        b[4] = s[9];
        s[5] ^= (~b[1]) & b[2];
        s[6] ^= (~b[2]) & b[3];
        s[7] ^= (~b[3]) & b[4];
        s[8] ^= (~b[4]) & b[0];
        s[9] ^= (~b[0]) & b[1];
        b[0] = s[10];
        b[1] = s[11];
        b[2] = s[12];
        b[3] = s[13];
        b[4] = s[14];
        s[10] ^= (~b[1]) & b[2];
        s[11] ^= (~b[2]) & b[3];
        s[12] ^= (~b[3]) & b[4];
        s[13] ^= (~b[4]) & b[0];
        s[14] ^= (~b[0]) & b[1];
        b[0] = s[15];
        b[1] = s[16];
        b[2] = s[17];
        b[3] = s[18];
        b[4] = s[19];
        s[15] ^= (~b[1]) & b[2];
        s[16] ^= (~b[2]) & b[3];
        s[17] ^= (~b[3]) & b[4];
        s[18] ^= (~b[4]) & b[0];
        s[19] ^= (~b[0]) & b[1];
        b[0] = s[20];
        b[1] = s[21];
        b[2] = s[22];
        b[3] = s[23];
        b[4] = s[24];
        s[20] ^= (~b[1]) & b[2];
        s[21] ^= (~b[2]) & b[3];
        s[22] ^= (~b[3]) & b[4];
        s[23] ^= (~b[4]) & b[0];
        s[24] ^= (~b[0]) & b[1];

        /* Iota */
        s[0] ^= rc[i];
    }

}

int crypto_hash(unsigned char *o, const unsigned char *m, unsigned long long l) {

    unsigned long long i, r = 136; /* SHAKE128 168, SHAKE256/SHA3256 136, SHA3512 72 */
    uint64_t s[25] = {0};
    unsigned char x[200];

    /* absorb all the input blocks */
    while (l >= r) {
        for (i = 0; i < r / 8; ++i) s[i] ^= unpack64(m + 8 * i);
        keccak(s);
        l -= r;
        m += r;
    }

    /* last block and padding */
    for (i = 0; i < l; ++i) x[i] = m[i];
    x[l++] = 0x1f; /* sha3 0x06, shake 0x1f */
    for (i = l; i < r; ++i) x[i] = 0;
    x[r - 1] |= 0x80;
    for (i = 0; i < r / 8; ++i) s[i] ^= unpack64(x + 8 * i);

    /* output */
    keccak(s);
    for (i = 0; i < crypto_hash_BYTES / 8; ++i) pack64(o + 8 * i, s[i]);

    return 0;
}
/* clang-format off */
