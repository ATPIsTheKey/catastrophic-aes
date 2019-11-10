//
// Created by roland on 2019-11-07.
//

#ifndef CATASTROPHIC_AES_CATASTROPHIC_AES_H
#define CATASTROPHIC_AES_CATASTROPHIC_AES_H

#include <stdint.h>

typedef struct aes_key {
    uint8_t *b;
    uint8_t  nk;
    uint8_t  nb;
    uint8_t  nr;
} aes_key_s;


void sub_bytes    (uint8_t *state);
void shift_rows   (uint8_t *state);
void mix_columns  (uint8_t *state);
void add_round_key(uint8_t *state);
void expand_key   (const aes_key_s *key, uint8_t *w);

#endif //CATASTROPHIC_AES_CATASTROPHIC_AES_H
