#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>
#define SODIUMINIT if (sodium_init() == -1) return 1

#include "catastrophic-aes/aes_core.h"
#include "catastrophic-aes/aes_utils.h"
#include "utils/stdprojutils.h"

#define PATH "/home/roland/CLionProjects/catastrophic-aes/tests/files"


int
main()
{
    uint8_t plain_b[16] = {
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
            0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
    };

    uint8_t key_b[16] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    aes_ctx_s *ctx = aes_ctx_init(key_b, KEY128);
    FILE *fp_plain = fopen(PATH"/plain", "rb");
    FILE *fp_encrypted = fopen(PATH"/encrypted.crypt", "wb");
    NP_CHECK(fp_plain)
    NP_CHECK(fp_encrypted)

    aes_ECB_encrypt_file(fp_plain, fp_encrypted, ctx);

    fclose(fp_plain);
    fclose(fp_encrypted);

    fp_encrypted = fopen(PATH"/encrypted.crypt", "rb");
    FILE *fp_decrypted = fopen(PATH"/decrypted", "wb");
    NP_CHECK(fp_encrypted)
    NP_CHECK(fp_decrypted)

    aes_ECB_decrypt_file(fp_encrypted, fp_decrypted, ctx);

    fclose(fp_encrypted);
    fclose(fp_decrypted);

    aes_ctx_destroy(ctx);
    return EXIT_SUCCESS;
}
