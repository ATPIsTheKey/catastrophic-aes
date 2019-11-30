//
// Created by roland on 2019-11-15.
//

#ifndef CATASTROPHIC_AES_FCRYPT_H
#define CATASTROPHIC_AES_FCRYPT_H

#include <stdio.h>
#include <stdint.h>
#include <caca.h>

#include "core.h"

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

int AES_prepare_fheader(aes_fheader_s *fheader, uint16_t opmode_magic, aes_ctx_s *ctx);
int AES_fread_fheader(aes_fheader_s *fheader, FILE *fp);

int AES_encrypt_file(FILE *fp_in, FILE *fp_out, uint16_t opmode_magic, const aes_ctx_s *ctx);
int AES_file_decrypt(FILE *fp_in, FILE *fp_out, const aes_ctx_s *ctx);

#endif //CATASTROPHIC_AES_FCRYPT_H
