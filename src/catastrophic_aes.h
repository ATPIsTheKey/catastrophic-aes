//
// Created by roland on 2019-11-07.
//

#ifndef CATASTROPHIC_AES_CATASTROPHIC_AES_H
#define CATASTROPHIC_AES_CATASTROPHIC_AES_H

#include <stdint.h>

void sub_bytes    (uint8_t *buff);
void shift_rows   (uint8_t *buff);
void mix_columns  (uint8_t *buff);
void add_round_key(uint8_t *buff);

#endif //CATASTROPHIC_AES_CATASTROPHIC_AES_H
