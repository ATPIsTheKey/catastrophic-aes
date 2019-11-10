#include <stdio.h>
#include <stdlib.h>

#include <sodium.h>
#define SODIUMINIT if (sodium_init() == -1) return 1

#include "src/catastrophic_aes.h"


int
main()
{
    SODIUMINIT; // todo: as of now useless.
    uint8_t key_b[32] = {
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };
    aes_key_s key = {
            .b = key_b,
            .nk = 8,
            .nb = 4,
            .nr = 14
    };
    uint8_t buff[240];
    expand_key(&key, buff);
    for (int i = 0; i < 240; i++)
        printf("0x%x ", buff[i]);
    return EXIT_SUCCESS;
}
