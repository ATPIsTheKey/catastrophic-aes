//
// Created by roland on 2019-11-15.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"
#include "../utils/stdprojutils.h"


input_buff_st*
input_buffered(FILE *fp, size_t buff_init_size)
{
    size_t buffsize = buff_init_size;

    input_buff_st *input = malloc(sizeof(input_buff_st));
    NP_CHECK(input)
    input->b = calloc(buffsize, sizeof(char));
    NP_CHECK(input->b)

    int c;
    size_t len = 0;
    while( EOF != (c=fgetc(fp)) && c != '\n' )
    {
        input->b[len++] = (char) c;
        if(len == buff_init_size) {
            input->b = realloc(
                    input->b, sizeof(char) * (buffsize += 16)
            );
            NP_CHECK(input->b)
        }
    }

    input->b[++len] ='\0';
    input->b        = realloc(input->b, len);
    input->len         = len;

    if (input->len == 1) {
        free(input->b);
        free(input);
        return NULL;
    }

    return input;
}


void
pw_input_destroy(input_buff_st *input)
{
    free(input->b);
    free(input);
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
