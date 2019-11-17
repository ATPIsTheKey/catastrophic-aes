#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>
#define SODIUMINIT if (sodium_init() == -1) return 1

#include "catastrophic-aes/fcrypt.h"
#include "utils/stdprojutils.h"

#define PATH "/home/roland/CLionProjects/catastrophic-aes/tests/files"


int
main() // todo: Extremely provisional tests. Implement better tests in near future.
{
    uint8_t plain_b[16] = {
            0x57, 0x68, 0x61, 0x74, 0x65, 0x76, 0x65, 0x72,
            0x2e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    uint8_t key_b[16] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    uint8_t encrypted_b[16];

    aes_ctx_s *ctx = aes_ctx_init(key_b, KEY128);
    FILE *fp_plain = fopen(PATH"/test_file.jpg", "rb");
    FILE *fp_encrypted = fopen(PATH"/test_file.crypt", "wb");
    NP_CHECK(fp_plain)
    NP_CHECK(fp_encrypted)

    aes_file_encrypt(fp_plain, fp_encrypted, CTR, ctx);

    fclose(fp_plain);
    fclose(fp_encrypted);

    fp_encrypted = fopen(PATH"/test_file.crypt", "rb");
    FILE *fp_decrypted = fopen(PATH"/test_file2.jpg", "wb");
    NP_CHECK(fp_encrypted)
    NP_CHECK(fp_decrypted)

    aes_file_decrypt(fp_encrypted, fp_decrypted, ctx);

    fclose(fp_encrypted);
    fclose(fp_decrypted);

    aes_ctx_destroy(ctx);
    return EXIT_SUCCESS;
}
