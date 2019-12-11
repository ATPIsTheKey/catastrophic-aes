//
// Created by roland on 2019-11-07.
//

#ifndef CATASTROPHIC_AES_CORE_H
#define CATASTROPHIC_AES_CORE_H

#include <stdint.h>

#define KEY128 128
#define KEY192 192
#define KEY256 256

/* data structures */
typedef struct __aes_core_key {
    uint8_t *b;
    uint8_t Nk;
    uint8_t Nb;
    uint8_t Nr;
} aes_core_key_st;

typedef struct __aes_core_ctx {
    aes_core_key_st *key;
    uint8_t   *expkey;
} aes_core_ctx_st;

/* initialize data structures */
aes_core_ctx_st *AES_CORE_ctx_init(uint8_t *key, uint32_t key_bitlen);
void AES_CORE_ctx_destroy(aes_core_ctx_st *ctx);

/* AES core operations */
void expand_key   (aes_core_key_st *key, uint8_t *w);
void sub_bytes    (uint8_t *state);
void shift_rows   (uint8_t *state);
void mix_columns  (uint8_t *state);
void add_round_key(uint8_t *state, const uint8_t *w, uint8_t r_i);

void inv_sub_bytes  (uint8_t *state);
void inv_shift_rows (uint8_t *state);
void inv_mix_columns(uint8_t *state);

/* AES block cipher operations */
void AES_CORE_cipher_block   (const uint8_t *in, uint8_t *out,
                              const aes_core_ctx_st *ctx);
void AES_CORE_invcipher_block(const uint8_t *in, uint8_t *out,
                              const aes_core_ctx_st *ctx);

#endif //CATASTROPHIC_AES_CORE_H
