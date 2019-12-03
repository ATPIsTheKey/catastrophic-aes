//
// Created by roland on 2019-11-15.
//

#ifndef CATASTROPHIC_AES_FILEOP_H
#define CATASTROPHIC_AES_FILEOP_H

#include <stdio.h>
#include <stdint.h>

#include "core.h"
#include "utils.h"

#define ECB  0xecb0
#define CBC  0xcbc0
#define CTR  0xc750
#define CFB  0xcfb0
#define OFB  0x0fb0


typedef struct __attribute__((__packed__)) __aes_fheader {
    uint16_t opmode_magic;
    uint8_t  init_vector[16];
    uint16_t salt_len;
    uint8_t  salt_vector[32];
} aes_fheader_s;


typedef struct __aes_fileop_enc_ctx {
    aes_core_ctx_s *core_ctx;
    uint16_t opmode_magic;
    uint8_t *pw_salt;
} aes_fileop_enc_ctx_s;

typedef struct __aes_fileop_decr_ctx {
    aes_core_ctx_s *core_ctx;
    pw_input_s *fcrypt_pw;
} aes_fileop_decr_ctx_s;


aes_fileop_enc_ctx_s* AES_FILEOP_enc_ctx_init(
        uint16_t opmode_magic, int32_t key_bitlen,
        pw_input_s *fcrypt_pw);

aes_fileop_enc_ctx_s* AES_FILEOP_decr_ctx_init(
        uint16_t opmode_magic, int32_t key_bitlen,
        pw_input_s *fcrypt_pw);

void AES_FILEOP_enc_ctx_destroy(aes_fileop_enc_ctx_s *ctx);
void AES_FILEOP_enc_decr_destroy(aes_fileop_enc_ctx_s *ctx);

int AES_FILEOP_prepare_fheader(aes_fheader_s *fheader, aes_fileop_enc_ctx_s *ctx);
int AES_FILEOP_fread_fheader(aes_fheader_s *fheader, FILE *fp);

int AES_FILEOP_encrypt_file(FILE *fp_in, FILE *fp_out, aes_fileop_enc_ctx_s *ctx);
int AES_FILEOP_decrypt_file(FILE *fp_in, FILE *fp_out, aes_fileop_decr_ctx_s *ctx);

#endif //CATASTROPHIC_AES_FILEOP_H
