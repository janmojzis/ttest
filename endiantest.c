#include <stdio.h>
#include <stdint.h>

int main(int argc, char **argv) {

    unsigned char x[4] = {1,2,3,4};
    uint32_t y;

    y = *(uint32_t *)x;

    fprintf(stderr, "y=%u\n", y);
    fflush(stderr);
    return 0;
}
