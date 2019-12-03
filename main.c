#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/utsname.h>

#include <openssl/rand.h>

#include "libs/argtable3.h"
#include "tests/src/aes_quicktest.h"
#include "catastrophic-aes/fileop.h"

#define PROGNAME "catastrophic-aes"
#define VERSION "1.0.0"

int
main(int argc, char **argv)
{
    pw_input_s pw;
    pw.buff = "5463vvdvdf";
    pw.len = 11;

    aes_fileop_enc_ctx_s *ctx = AES_FILEOP_enc_ctx_init(CBC, KEY128, &pw);
    AES_FILEOP_enc_ctx_destroy(ctx);

    for (int i = 0; i < 16; ++i)
        printf("%x ", ctx->core_ctx->key->b[i]);

    return 0;
}