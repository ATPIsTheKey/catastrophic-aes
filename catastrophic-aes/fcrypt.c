//
// Created by roland on 2019-11-15.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rand.h>

#include "core.h"
#include "fcrypt.h"

#define NBYTES_STATE 16


static void
xor_buff(uint8_t *a, const uint8_t *b, size_t b_len) {
    for (size_t i = 0; i < b_len; i++)
        a[i] ^= b[i];
}


static int
aes_ECB_encrypt_file(FILE *fp_in, FILE *fp_out, const aes_ctx_s *ctx) {
    uint8_t plain_b[16], enc_b[16];
    size_t b_read = 0;

    aes_fheader_s fheader = {.cipher_opmode = {'E', 'C', 'B', '\0', '\0'}};
    memset(fheader.init_vector, '\0', sizeof(fheader.init_vector));

    fwrite(&fheader, sizeof(aes_fheader_s), sizeof(uint8_t), fp_out);
    while ((b_read = fread(plain_b, 1, sizeof(plain_b), fp_in)) == 16) {
        aes_cipher_block(plain_b, enc_b, ctx);
        fwrite(enc_b, NBYTES_STATE * sizeof(uint8_t), 1, fp_out);
    }

    if (b_read) { // add padding
        for (size_t i = b_read; i < 16; i++)
            plain_b[i] = '\0';
        aes_cipher_block(plain_b, enc_b, ctx);
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


static int
aes_CBC_encrypt_file(FILE *fp_in, FILE *fp_out, const aes_ctx_s *ctx)
{
    uint8_t plain_b[16], enc_b[16];
    size_t b_read = 0;

    aes_fheader_s fheader = {.cipher_opmode = {'C', 'B', 'C', '\0', '\0'}};
    if (RAND_bytes(fheader.init_vector, 16) != 1) return 0;
    memcpy(enc_b, fheader.init_vector, 16 * sizeof(uint8_t));

    fwrite(&fheader, sizeof(aes_fheader_s), sizeof(uint8_t), fp_out);
    while ((b_read = fread(plain_b, 1, sizeof(plain_b), fp_in)) == 16) {
        xor_buff(plain_b, enc_b, NBYTES_STATE);
        aes_cipher_block(plain_b, enc_b, ctx);
        fwrite(enc_b, NBYTES_STATE * sizeof(uint8_t), 1, fp_out);
    }

    if (b_read) { // add padding
        for (size_t i = b_read; i < 16; i++)
            plain_b[i] = '\0';
        xor_buff(plain_b, enc_b, NBYTES_STATE);
        aes_cipher_block(plain_b, enc_b, ctx);
        fwrite(enc_b, NBYTES_STATE * sizeof(uint8_t), 1, fp_out);
    }

    return 1;
}


static int
aes_CBC_decrypt_file(
        FILE *fp_in, FILE *fp_out, const aes_ctx_s *ctx, uint8_t *init_vector)
{
    uint8_t enc_b[16], plain_b[16], enc_b_prev[16];
    memcpy(enc_b_prev, init_vector, NBYTES_STATE * sizeof(uint8_t));

    while (fread(enc_b, 1, sizeof(enc_b), fp_in)) {
        aes_invcipher_block(enc_b, plain_b, ctx);
        xor_buff(plain_b, enc_b_prev, NBYTES_STATE);
        fwrite(plain_b, NBYTES_STATE * sizeof(uint8_t), 1, fp_out);
        memcpy(enc_b_prev, enc_b, NBYTES_STATE);
    }

    return 1;
}


static int
aes_CTR_encrypt(FILE *fp_in, FILE *fp_out, const aes_ctx_s *ctx)
{
    uint8_t plain_b[16], enc_b[16];
    // nonce_ctr buffer holds nonce bytes and counter
    uint64_t *nonce_ctr = calloc(2, sizeof(uint64_t));
    size_t b_read = 0;

    aes_fheader_s fheader = {.cipher_opmode = {'C', 'T', 'R', '\0', '\0'}};
    if (RAND_bytes( (uint8_t*) nonce_ctr, 8) != 1) return 0;
    // in CTR mode init vector is used to store 8 byte nonce value
    memcpy(fheader.init_vector, nonce_ctr, sizeof(nonce_ctr[0]));

    fwrite(&fheader, sizeof(aes_fheader_s), sizeof(uint8_t), fp_out);
    while ((b_read = fread(plain_b, 1, sizeof(plain_b), fp_in)) == 16) {
        aes_cipher_block( (uint8_t*) nonce_ctr, enc_b, ctx);
        xor_buff(enc_b, plain_b, NBYTES_STATE);
        fwrite(enc_b, NBYTES_STATE * sizeof(uint8_t), 1, fp_out);
        nonce_ctr[1]++; // increment counter
    }

    if (b_read) { // add padding
        for (size_t i = b_read; i < 16; i++)
            plain_b[i] = '\0';
        aes_cipher_block( (uint8_t*) nonce_ctr, enc_b, ctx);
        xor_buff(enc_b, plain_b, NBYTES_STATE);
        fwrite(enc_b, NBYTES_STATE * sizeof(uint8_t), 1, fp_out);
    }

    printf("%lu", nonce_ctr[1]);

    return 1;
}


static int
aes_CTR_decrypt_file(
        FILE *fp_in, FILE *fp_out, const aes_ctx_s *ctx, uint8_t *init_vector)
{
    uint8_t enc_b[16], plain_b[16];
    uint64_t *nonce_ctr = calloc(2, sizeof(uint64_t));

    // copy 8 bytes nonce value of init vector into first 8 bytes of nonce_ctr buffer
    memcpy(nonce_ctr, init_vector, 2 * sizeof(uint64_t));

    while (fread(enc_b, 1, sizeof(enc_b), fp_in)) {
        aes_invcipher_block( (uint8_t*) nonce_ctr, plain_b, ctx);
        xor_buff(plain_b, enc_b, NBYTES_STATE);
        fwrite(plain_b, NBYTES_STATE * sizeof(uint8_t), 1, fp_out);
        nonce_ctr[1]++;
    }

    return 1;
}

int
aes_file_encrypt(FILE *fp_in, FILE *fp_out, int opmode_hash, aes_ctx_s *ctx) {
    switch (opmode_hash) {
        case ECB:
            aes_ECB_encrypt_file(fp_in, fp_out, ctx);
            break;
        case CBC:
            aes_CBC_encrypt_file(fp_in, fp_out, ctx);
            break;
        case PCBC:
            break;
        case CFB:
            break;
        case OFB:
            break;
        case CTR:
            aes_CTR_encrypt(fp_in, fp_out, ctx);
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
            aes_CBC_decrypt_file(fp_in, fp_out, ctx, init_vector);
            break;
        case PCBC:
            break;
        case CFB:
            break;
        case OFB:
            break;
        case CTR:
            aes_CTR_decrypt_file(fp_in, fp_out, ctx, init_vector);
            break;
        default:
            return 0;
    }
    return 1;
}

