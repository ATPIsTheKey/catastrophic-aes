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
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
            0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
    };

    uint8_t key_b[16] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    uint8_t encrypted_b[16];
    uint8_t decrypted_b[16];

    aes_ctx_s *ctx = aes_ctx_init(key_b, KEY128);

    aes_cipher_block(plain_b, encrypted_b, ctx);
    for (int i = 0; i < 16; i++)
        printf("0x%0x ", encrypted_b[i]);
    printf("\n");

    aes_invcipher_block(encrypted_b, decrypted_b, ctx);
    for (int i = 0; i < 16; i++)
        printf("0x%0x ", decrypted_b[i]);
    printf("\n");

    aes_ctx_destroy(ctx);
    return EXIT_SUCCESS;
}
