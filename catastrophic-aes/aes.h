//
// Created by roland on 2019-11-07.
//

#ifndef CATASTROPHIC_AES_AES_H
#define CATASTROPHIC_AES_AES_H

#include <stdint.h>

#define KEY128 128
#define KEY192 192
#define KEY256 256

typedef struct aes_key {
    uint8_t *b;
    uint8_t  nk;
    uint8_t  nb;
    uint8_t  nr;
} aes_key_s;

typedef struct aes_ctx {
    aes_key_s *key;
    uint8_t   *expkey;
} aes_ctx_s;

/* data structures */
aes_ctx_s *aes_ctx_init(uint8_t *key, uint16_t key_bitlen);
void aes_ctx_destroy(aes_ctx_s *ctx);

/* aes core operations */
void expand_key   (const aes_key_s *key, uint8_t *w);
void sub_bytes    (uint8_t *state);
void shift_rows   (uint8_t *state);
void mix_columns  (uint8_t *state);
void add_round_key(uint8_t *state, const uint8_t *w, uint8_t r_i);

void inv_sub_bytes  (uint8_t *state);
void inv_shift_rows (uint8_t *state);
void inv_mix_columns(uint8_t *state);

/* aes encryption/decryption operations */
void aes_cipher_block   (uint8_t *in, uint8_t *out, const aes_ctx_s *ctx);
void aes_invcipher_block(uint8_t *in, uint8_t *out, const aes_ctx_s *ctx);

#endif //CATASTROPHIC_AES_AES_H
