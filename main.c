#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/utsname.h>

#include <openssl/rand.h>

#include "libs/argtable3.h"
#include "tests/src/aes_quicktest.h"
#include "catastrophic-aes/core.h"
#include "catastrophic-aes/fileop.h"

#define PROGNAME "catastrophic-aes"
#define VERSION "1.0.0"

#define PLAINTESTFILE "/home/roland/CLionProjects/catastrophic-aes/tests/files/test_file.jpg"
#define CRYPTTESTFILE "/home/roland/CLionProjects/catastrophic-aes/tests/files/test_file.jpg.crypt"
#define DECRYPTTESTFILE "/home/roland/CLionProjects/catastrophic-aes/tests/files/test_file_decrypt.jpg"

int
main(int argc, char **argv)
{
    input_buff_st pw;
    pw.b = "5463vvdvdf";
    pw.len = 11;

    input_buff_st pw2;
    pw2.b = "5463vvdvdf";
    pw2.len = 11;

    aes_fileop_ctx_st *encryption_ctx = AES_FILEOP_filecrypt_ctx_init(
        &pw, CBC, KEY128
        );

    FILE *fp_plain = fopen(PLAINTESTFILE, "rb");
    FILE *fp_enc   = fopen(CRYPTTESTFILE, "wb");
    FILE *fp_decr  = fopen(DECRYPTTESTFILE, "wb");

    AES_CBC_encrypt_file(fp_plain, fp_enc, encryption_ctx);
    fclose(fp_enc);

    fp_enc   = fopen(CRYPTTESTFILE, "rb");
    AES_CBC_decrypt_file(fp_enc, fp_decr, &pw2);

    AES_FILEOP_filecrypt_ctx_destroy(encryption_ctx);
    return 0;
}
