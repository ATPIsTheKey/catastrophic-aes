//
// Created by roland on 2019-11-15.
//

#ifndef CATASTROPHIC_AES_AES_FCRYPT_H
#define CATASTROPHIC_AES_AES_FCRYPT_H

#include <stdio.h>
#include <stdint.h>

#include "aes_core.h"

// todo: better hashing of opmodes
/* Integer codes derived by summing ascii values of chars of cipher mode
 * name together. Luckily, no collisions. */
#define ECB  202
#define CBC  200
#define PCBC 280
#define CFB  203
#define OFB  215
#define CTR  233


typedef struct __attribute__((__packed__)) __aes_fheader {
    uint8_t cipher_opmode[5];
    uint8_t init_vector[16];
} aes_fheader_s;


int aes_file_encrypt(FILE *fp_in, FILE *fp_out, int opmode_hash, aes_ctx_s *ctx);
int aes_file_decrypt(FILE *fp_in, FILE *fp_out, aes_ctx_s *ctx);

#endif //CATASTROPHIC_AES_AES_FCRYPT_H
