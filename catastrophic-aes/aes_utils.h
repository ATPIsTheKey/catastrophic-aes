//
// Created by roland on 2019-11-15.
//

#ifndef CATASTROPHIC_AES_AES_UTILS_H
#define CATASTROPHIC_AES_AES_UTILS_H

#include <stddef.h>
#include <stdint.h>

typedef struct __pw_input {
    char *buff;
    size_t len;
} pw_input_s;

/* dynamic length input function */
pw_input_s *input_pw(FILE *fp, size_t buff_init_size);

void pw_input_destroy(pw_input_s *input);

/* convert hex string to hex buffer */
int hexstr_to_bin(char *hexstr, uint8_t *out);

#endif //CATASTROPHIC_AES// _UTILS_H
