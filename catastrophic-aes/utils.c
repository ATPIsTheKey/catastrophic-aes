//
// Created by roland on 2019-11-15.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "utils.h"
#include "../utils/stdprojutils.h"


typedef struct __pw_input {
    char *buff;
    size_t len;
} pw_input_s;


static pw_input_s*
input_pw(FILE *fp, size_t buff_init_size)
{
    size_t buffsize = buff_init_size;

    pw_input_s *input = malloc(sizeof(pw_input_s));
    NP_CHECK(input)
    input->buff = calloc(buffsize, sizeof(char));
    NP_CHECK(input->buff)

    int c;
    size_t len = 0;
    while( EOF != (c=fgetc(fp)) && c != '\n' )
    {
        input->buff[len++] = (char) c;
        if(len == buff_init_size) {
            input->buff = realloc(
                    input->buff, sizeof(char) * (buffsize += 16)
            );
            NP_CHECK(input->buff)
        }
    }

    input->buff[++len] ='\0';
    input->buff        = realloc(input->buff, len);
    input->len         = len;

    if (input->len == 1) {
        free(input->buff);
        free(input);
        return NULL;
    }

    return input;
}


static void
pw_input_destroy(pw_input_s *input)
{
    free(input->buff);
    free(input);
}


pwderiv_key_s*
pwderiv_input(int kblen, char *prompt) // todo: remove completely as salt public
{
    pwderiv_key_s *derivkey = malloc(sizeof(pwderiv_key_s)); NP_CHECK(derivkey)
    derivkey->len = (uint8_t) kblen;
    derivkey->salt = calloc(kblen, sizeof(uint8_t)); NP_CHECK(derivkey->salt)
    derivkey->key  = calloc(kblen, sizeof(uint8_t)); NP_CHECK(derivkey->key)

    printf("%s", prompt);
    pw_input_s *input = input_pw(stdin, 24); NP_CHECK(input)

    RAND_bytes(derivkey->salt, kblen * (int) sizeof(uint8_t));
    PKCS5_PBKDF2_HMAC_SHA1(
            input->buff, input->len,
            derivkey->salt, kblen, 1000,
            derivkey->len, derivkey->key
    );

    pw_input_destroy(input);
    return derivkey;
}


void
pwderiv_destroy(pwderiv_key_s *derivkey)
{
    free(derivkey);
}


// Based on https://stackoverflow.com/questions/3408706/hexadecimal-string-to-byte-array-in-c
int hexstr_to_bin(char *hexstr, uint8_t *dest_buffer) {
    char *ln = hexstr, *data = ln;
    int offset, read_byte, data_len = 0;

    while (sscanf(data, " %02x%n", &read_byte, &offset) == 1) {
        dest_buffer[data_len++] = read_byte;
        data += offset;
    }
    return data_len;
}
