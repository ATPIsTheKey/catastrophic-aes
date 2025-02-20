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
    uint8_t  init_vec[16];
    uint16_t key_salt_len;
    uint8_t  salt_vec[32];
} aes_fheader_st;


typedef struct __aes_fileop_ctx {
    uint16_t       opmode_magic;
    uint8_t       *key_vec;
    uint16_t       key_bitlen;
    uint8_t       *salt_vec;
    uint16_t       salt_len;
} aes_fileop_ctx_st;


aes_fileop_ctx_st *AES_FILEOP_filecrypt_ctx_init(
        input_buff_st *inpw, uint16_t opmode_magic, uint16_t key_bitlen);
void AES_FILEOP_filecrypt_ctx_destroy(aes_fileop_ctx_st *ctx);

int AES_FILEOP_encrypt_file(FILE *fp_in, FILE *fp_out, aes_fileop_ctx_st *ctx);
int AES_FILEOP_decrypt_file(FILE *fp_in, FILE *fp_out, input_buff_st *inpw);

#endif //CATASTROPHIC_AES_FILEOP_H
