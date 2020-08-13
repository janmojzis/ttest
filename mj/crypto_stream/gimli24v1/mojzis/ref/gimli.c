/*
20200202
Jan Mojzis
Public domain.
*/

#include <stdint.h>
#include "crypto_stream.h"

/* clang-format off */
static inline uint32_t unpack(const unsigned char *x) {
    return
        (uint32_t) (x[0])                  \
    | (((uint32_t) (x[1])) << 8)           \
    | (((uint32_t) (x[2])) << 16)          \
    | (((uint32_t) (x[3])) << 24);
}

static inline void pack(unsigned char *x, uint32_t u) {
    x[0] = u; u >>= 8;
    x[1] = u; u >>= 8;
    x[2] = u; u >>= 8;
    x[3] = u;
}

#define ROTATE(x, c) ((x) << (c)) ^ ((x) >> (32 - (c)))

static void gimli(uint32_t *state) {

    int round;
    uint32_t x, y, z;

    for (round = 24; round > 0; --round) {

        x = ROTATE(state[ 0], 24);
        y = ROTATE(state[ 4],  9);
        z =        state[ 8];
        state[ 8] = x ^ (z << 1) ^ ((y & z) << 2);
        state[ 4] = y ^ x        ^ ((x | z) << 1);
        state[ 0] = z ^ y        ^ ((x & y) << 3);
        x = ROTATE(state[ 1], 24);
        y = ROTATE(state[ 5],  9);
        z =        state[ 9];
        state[ 9] = x ^ (z << 1) ^ ((y & z) << 2);
        state[ 5] = y ^ x        ^ ((x | z) << 1);
        state[ 1] = z ^ y        ^ ((x & y) << 3);
        x = ROTATE(state[ 2], 24);
        y = ROTATE(state[ 6],  9);
        z =        state[10];
        state[10] = x ^ (z << 1) ^ ((y & z) << 2);
        state[ 6] = y ^ x        ^ ((x | z) << 1);
        state[ 2] = z ^ y        ^ ((x & y) << 3);
        x = ROTATE(state[ 3], 24);
        y = ROTATE(state[ 7],  9);
        z =        state[11];
        state[11] = x ^ (z << 1) ^ ((y & z) << 2);
        state[ 7] = y ^ x        ^ ((x | z) << 1);
        state[ 3] = z ^ y        ^ ((x & y) << 3);

        if ((round & 3) == 0) { /* small swap: pattern s...s...s... etc. */
            x = state[0]; state[0] = state[1]; state[1] = x;
            x = state[2]; state[2] = state[3]; state[3] = x;
        }

        if ((round & 3) == 2) { /* big swap: pattern ..S...S...S. etc. */
            x = state[0]; state[0] = state[2]; state[2] = x;
            x = state[1]; state[1] = state[3]; state[3] = x;
        }

        if ((round & 3) == 0) { /* add constant: pattern c...c...c... etc. */
            state[0] ^= (0x9e377900 | round);
        }
    }
}

#define ROTATE(x, c) ((x) << (c)) ^ ((x) >> (32 - (c)))

#if 0
int crypto_stream(unsigned char *c, unsigned long long l, const unsigned char *n, const unsigned char *k) {

    int round;
    vec newy;
    vec newz;
    vec x = unpack(n);
    vec y = unpack(k);
    vec z = unpack(k + 16);

    GIMLI;

    while (l >= 16) {
        pack(c, x);
        GIMLI;
        c += 16;
        l -= 16;
    }

    if (l > 0) {
        unsigned char buf[16] = {0};
        long long i;
        pack(buf, x);
        for (i = 0; i < l; ++i) c[i] = buf[i];
    }

    return 0;
}
#endif

int crypto_stream_xor(unsigned char *c, const unsigned char *m, unsigned long long l, const unsigned char *n, const unsigned char *k) {


    long long i;
    uint32_t s[12];
    long long round;

    for (i = 0; i < 4; ++i) s[i    ] = unpack(n + 4 * i);
    for (i = 0; i < 8; ++i) s[i + 4] = unpack(k + 4 * i);

    while (l >= 16) {
        gimli(s);
        for (i = 0; i < 4; ++i) pack(c + 4 * i, s[i] ^ unpack(m + 4 * i));
        c += 16;
        m += 16;
        l -= 16;
    }

    if (l > 0) {
        unsigned char buf[16] = {0};
        gimli(s);
        for (i = 0; i < l; ++i) buf[i] = m[i];
        for (i = 0; i < 4; ++i) pack(buf + 4 * i, s[i] ^ unpack(m + 4 * i));
        for (i = 0; i < l; ++i) c[i] = buf[i];
    }

    return 0;
}


int crypto_stream(unsigned char *c, unsigned long long l, const unsigned char *n, const unsigned char *k) {

    long long i;
    uint32_t s[12];
    long long round;

    for (i = 0; i < 4; ++i) s[i    ] = unpack(n + 4 * i);
    for (i = 0; i < 8; ++i) s[i + 4] = unpack(k + 4 * i);

    while (l >= 16) {
        gimli(s);
        for (i = 0; i < 4; ++i) pack(c + 4 * i, s[i]);
        c += 16;
        l -= 16;
    }

    if (l > 0) {
        unsigned char buf[16] = {0};
        gimli(s);
        for (i = 0; i < 4; ++i) pack(buf + 4 * i, s[i]);
        for (i = 0; i < l; ++i) c[i] = buf[i];
    }

    return 0;
}
