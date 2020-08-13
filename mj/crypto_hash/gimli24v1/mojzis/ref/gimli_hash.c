/*
20200202
Jan Mojzis
Public domain.
*/

#include <stdint.h>
#include "crypto_hash.h"

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

int crypto_hash(unsigned char *o, const unsigned char *m, unsigned long long l) {

    long long i;
    uint32_t s[12] = {0};
    unsigned char x[48] = {0};

    /* absorb all the input blocks */
    while (l >= 16) {
        for (i = 0; i < 4; ++i) s[i] ^= unpack(m + 4 * i);
        gimli(s);
        l -= 16;
        m += 16;
    }

    /* last block and padding */
    for (i = 0; i < l; ++i) x[i] = m[i];
    x[i] = 1;
    x[sizeof x - 1] = 1;
    for (i = 0; i < 12; ++i) s[i] ^= unpack(x + 4 * i);

    /* output */
    gimli(s);
    for (i = 0; i < 4; ++i) pack(o + 4 * i     , s[i]);
    gimli(s); 
    for (i = 0; i < 4; ++i) pack(o + 4 * i + 16, s[i]);
    return 0;
}
/* clang-format off */
