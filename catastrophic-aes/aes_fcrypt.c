//
// Created by roland on 2019-11-15.
//

#include <openssl/rand.h>

#include "aes_core.h"
#include "aes_fcrypt.h"

#define NBYTES_STATE 16


static int
aes_ECB_encrypt_file(FILE *fp_in, FILE *fp_out, const aes_ctx_s *ctx) {
    uint8_t plain_b[16], enc_b[16];
    size_t b_read = 0;

    aes_fheader_s fheader = {.cipher_mode = {'E', 'C', 'B', '\0', '\0'}};
    if (RAND_bytes(fheader.init_vector, 16) != 1) return 0;

    fwrite(&fheader, sizeof(aes_fheader_s), sizeof(uint8_t), fp_out);
    while ((b_read = fread(plain_b, 1, sizeof(plain_b), fp_in)) == 16) {
        aes_cipher_block(plain_b, enc_b, ctx);
        fwrite(enc_b, NBYTES_STATE * sizeof(uint8_t), 1, fp_out);
    }

    if (b_read) { // add padding
        for (size_t i = b_read - 1; i < 16; i++)
            plain_b[i] = '\0';
        fwrite(enc_b, NBYTES_STATE * sizeof(uint8_t), 1, fp_out);
    }
    return 1;
}


static int
aes_ECB_decrypt_file(FILE *fp_in, FILE *fp_out, const aes_ctx_s *ctx) {
    uint8_t enc_b[16], plain_b[16];

    while (fread(enc_b, 1, sizeof(enc_b), fp_in)) {
        aes_invcipher_block(enc_b, plain_b, ctx);
        fwrite(plain_b, NBYTES_STATE * sizeof(uint8_t), 1, fp_out);
    }

    return 1;
}


int
aes_file_encrypt(FILE *fp_in, FILE *fp_out, int mode_hash, aes_ctx_s *ctx) {
    switch (mode_hash) {
        case ECB:
            aes_ECB_encrypt_file(fp_in, fp_out, ctx);
            break;
        case CBC:
            break;
        case PCBC:
            break;
        case CFB:
            break;
        case OFB:
            break;
        case CTR:
            break;
        default:
            return 0;
    }
    return 1;
}


int
aes_file_decrypt(FILE *fp_in, FILE *fp_out, aes_ctx_s *ctx) {
    uint8_t cipher_mode[5];
    fread(cipher_mode, sizeof(cipher_mode), 1, fp_in);
    uint8_t init_vector[16];
    fread(init_vector, sizeof(init_vector), 1, fp_in);

    int mode_hash = cipher_mode[0] + cipher_mode[1] + cipher_mode[2]
                    + cipher_mode[3] + cipher_mode[4];
    switch (mode_hash) {
        case ECB:
            aes_ECB_decrypt_file(fp_in, fp_out, ctx);
            break;
        case CBC:
            break;
        case PCBC:
            break;
        case CFB:
            break;
        case OFB:
            break;
        case CTR:
            break;
        default:
            return 0;
    }
    return 1;
}

