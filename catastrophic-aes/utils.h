//
// Created by roland on 2019-11-15.
//

#ifndef CATASTROPHIC_AES_UTILS_H
#define CATASTROPHIC_AES_UTILS_H

#include <stddef.h>
#include <stdint.h>

typedef struct __attribute__((__packed__)) __pwderiv_key {
    uint8_t len;
    uint8_t *salt;
    uint8_t *key;
} pwderiv_key_s;


pwderiv_key_s* pwderiv_input(int kblen, char *prompt);
void pwderiv_destroy(pwderiv_key_s *derivkey);

/* convert hex string to hex buffer */
int hexstr_to_bin(char *hexstr, uint8_t *out);

#endif //CATASTROPHIC_AES// _UTILS_H
