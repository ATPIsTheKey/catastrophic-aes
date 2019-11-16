//
// Created by roland on 2019-11-15.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aes_utils.h"
#include "../utils/stdprojutils.h"


pw_input_s*
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
    printf("\n");

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


void
pw_input_destroy(pw_input_s *input)
{
    free(input->buff);
    free(input);
}

// Based on https://stackoverflow.com/questions/3408706/hexadecimal-string-to-byte-array-in-c
int hexstr_to_bin(char *hexstr, uint8_t *dest_buffer) {
    char *line = hexstr, *data = line;
    int offset, read_byte, data_len = 0;

    while (sscanf(data, " %02x%n", &read_byte, &offset) == 1) {
        dest_buffer[data_len++] = read_byte;
        data += offset;
    }
    return data_len;
}
