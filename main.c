#include <stdio.h>
#include <stdlib.h>

#include <sodium.h>
#define SODIUMINIT if (sodium_init() == -1) return 1

#include "catastrophic-aes/aes.h"

int
main()
{
    SODIUMINIT; // todo: as of now useless.
    uint8_t plain_b[16] = {
            0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
            0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
    };

    uint8_t key_b[32] = {
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
            0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
            0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
            0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };

    uint8_t *encrypted_b = malloc(16 * sizeof(uint8_t));
    aes_ctx_s *ctx = aes_ctx_init(key_b, KEY256);

    aes_cipher_block(plain_b, encrypted_b, ctx);
    aes_decipher_block(encrypted_b, plain_b, ctx);
    for (int i = 0; i < 16; i++)
        printf("%x", encrypted_b[i]);
    printf("\n");

    aes_ctx_destroy(ctx);
    return EXIT_SUCCESS;
}
