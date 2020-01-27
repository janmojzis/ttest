#include <stdio.h>
#include <stdint.h>

static void hprint(unsigned char *h, long long hlen) {
    long long i;
    for (i = 0; i < hlen; ++i)
        fprintf(stderr, "%02x", 255 & (int)h[i]);
    fprintf(stderr, "\n");
    fflush(stderr);
}

int main(int argc, char **argv) {

    unsigned char x[4] = {1,2,3,4};

    y = *(uint32_t *)x;

    printf("%u\n", y);
    return 0;
}
