#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "libs/argtable3.h"
#include "tests/src/aes_quicktest.h"
#include "catastrophic-aes/utils.h"


/* global arg_xxx structs */
struct arg_lit *verb, *help, *version, *opmode;
struct arg_int *klen;
struct arg_file *o, *file;
struct arg_end *end;

int
main(int argc, char **argv)
{
    /*** Initialize arg parser *****************************************************/

    /* the global arg_xxx structs are initialised within the argtable */
    void *argtable[] = {
            verb    = arg_litn("v", "verbose", 0, 1, "verbose output"),
            help    = arg_litn(NULL, "help", 0, 1, "display this help and exit"),
            version = arg_litn(NULL, "version", 0, 1, "display version info and exit"),
            o       = arg_filen("o", NULL, "myfile", 1, 1, "output file"),
            file    = arg_filen(NULL, NULL, "<file>", 1, 1, "input files"),
            klen    = arg_intn("k", "klen", "<n>", 0, 1, "AES key length of either 128, 192 or 256; default is 128"),
            opmode  = arg_litn("c", "mode", 0, 1, "set block cipher mode of operation; default is CBC"),
            end     = arg_end(20),
    };

    int exitcode = 0;
    char progname[] = "catastrophicaes";

    int nerrors;
    nerrors = arg_parse(argc,argv,argtable);

    /* special case: '--help' takes precedence over error reporting */
    if (help->count > 0)
    {
        printf("Usage: %s", progname);
        arg_print_syntax(stdout, argtable, "\n");
        printf("Demonstrate command-line parsing in argtable3.\n\n");
        arg_print_glossary(stdout, argtable, "  %-25s %s\n");
        exitcode = 0;
        goto exit;
    }

    /* If the parser returned any errors then display them and exit */
    if (nerrors > 0)
    {
        /* Display the error details contained in the arg_end struct.*/
        arg_print_errors(stdout, end, progname);
        printf("Try '%s --help' for more information.\n", progname);
        exitcode = 1;
        goto exit;
    }

    /*** begin encryption procedure ************************************************/

    char full_path_in[PATH_MAX];
    char full_path_out[PATH_MAX];
    sprintf(full_path_in, "%s", file->filename[0]);
    sprintf(full_path_out, "%s.crypt", o->filename[0]);

    FILE *fp_in   = fopen(full_path_in, "rb");
    FILE *fp_out  = fopen(full_path_out, "wb+");
//    FILE *key_out = fopen("")

    pw_input_s *pw = input_pw(stdin, 32);

    exit:
    /* deallocate each non-null entry in argtable[] */
    arg_freetable(argtable, sizeof(argtable) / sizeof(argtable[0]));
    return exitcode;
}
