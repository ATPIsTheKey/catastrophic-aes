//
// Created by roland on 2019-11-15.
//

#ifndef CATASTROPHIC_AES_AES_UTILS_H
#define CATASTROPHIC_AES_AES_UTILS_H

#include <stddef.h>

typedef struct pw_input {
    char *buff;
    size_t len;
} pw_input_s;

pw_input_s *input_pw (FILE *fp, size_t buff_init_size);
void pw_input_destroy(pw_input_s *input);


#endif //CATASTROPHIC_AES// _UTILS_H
