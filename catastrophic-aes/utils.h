//
// Created by roland on 2019-11-15.
//

#ifndef CATASTROPHIC_AES_UTILS_H
#define CATASTROPHIC_AES_UTILS_H

#include <stddef.h>
#include <stdint.h>

typedef struct __input_buff {
    char  *b;
    size_t len;
} input_buff_st;

input_buff_st *input_buffered(FILE *fp, size_t buff_init_size);
void pw_input_destroy(input_buff_st *input);

/* convert hex string to hex buffer */
int hexstr_to_bin(char *hexstr, uint8_t *out);

#endif //CATASTROPHIC_AES// _UTILS_H
