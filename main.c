#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <regex.h>

#include "libs/argtable3.h"
#include "tests/src/aes_quicktest.h"
#include "catastrophic-aes/utils.h"

#define VERSION "1.0"

/* SYNTAX 1: encrypt */
struct arg_rex *cmd1;
struct arg_lit *opmode, *verb1, *help1, *vers1;
struct arg_int *klen;
struct arg_file *o1, *file1, *fkey1;
struct arg_end *end1;
int nerrors1;

/* SYNTAX 2: decrypt */
struct arg_rex *cmd2;
struct arg_lit *verb2, *help2, *vers2;
struct arg_file *o2, *file2, *fkey2;
struct arg_end *end2;
int nerrors2;

/* SYNTAX 3: help or version*/
struct arg_lit *help3;
struct arg_lit *vers3;
struct arg_end *end3;
int nerrors3;

int
mainprocedure_encryption()
{
    return 0;
}

int
mainprocedure_decryption()
{
    return 0;
}

int
mainprocedure_help(int help, int version, const char *progname,
                   void *argtable1, void *argtable2, void *argtable3)
{
    if (help) {
        printf("Usage: %s", progname);
        arg_print_syntax(stdout, argtable1, "\n");
        printf("       %s", progname);
        arg_print_syntax(stdout, argtable2, "\n");
        printf("       %s", progname);
        arg_print_syntax(stdout, argtable3, "\n");
        printf("       %s", progname);
        printf("This program encrypts/decrypts files by the Advanced "
               "Encryption Standard.\n");
        arg_print_glossary(stdout, argtable1, "      %-20s %s\n");
        arg_print_glossary(stdout, argtable2, "      %-20s %s\n");
        arg_print_glossary(stdout, argtable3, "      %-20s %s\n");
    }

    if (version)
    {
        printf("%s version "VERSION, progname);
        printf("There is NO warranty; not even for MERCHANTABILITY or "
               "FITNESS FOR A PARTICULAR PURPOSE.");
        return 0;
    }
    printf("Try '%s --help' for more information.\n", progname);

    return 0;
}


int
main(int argc, char **argv)
{
    /*** Initialize arg parser ************************************************/

    /// Argtable 1 for encryption command //////////////////////////////////////

    void *argtable1[] = {
        cmd1   = arg_rex1(
                NULL, NULL, "encrypt", NULL, REG_ICASE,
                "encrypt a file"
        ),

        verb1  = arg_litn(
                "v", "verbose", 0, 1,
                "verbose output"
        ),

        help1  = arg_litn(
                NULL, "help", 0, 1,
                "display this help and exit"
        ),

        vers1  = arg_litn(
                NULL, "version", 0, 1,
                "display version info and exit"
        ),

        o1      = arg_filen(
                "o", NULL, "<file>", 1, 1,
                "output encrypted file"
        ),

        file1   = arg_filen(
                NULL, NULL, "<file>", 1, 1,
                "input file to be encrypted"
        ),

        fkey2   = arg_filen(
                NULL, NULL, "<file>", 0, 1,
                "output for file key (optional only)"
        ),

        klen = arg_intn(
                "l", "klen", "<int>", 0, 1,
                "key length of either 128, 192 or 256 (default is 128)"
        ),

        end1   = arg_end(9)
    };

    /// Argtable 2 for decryption command //////////////////////////////////////

    void *argtable2[] = {
            cmd2   = arg_rex1(
                    NULL, NULL, "decrypt", NULL, REG_ICASE,
                    "decrypt a file"
            ),

            verb2  = arg_litn(
                    "v", "verbose", 0, 1,
                    "verbose output"
            ),

            help2  = arg_litn(
                    NULL, "help", 0, 1,
                    "display this help and exit"
            ),

            vers2  = arg_litn(
                    NULL, "version", 0, 1,
                    "display version info and exit"
            ),

            o2      = arg_filen(
                    "o", NULL, "myfile", 1, 1,
                    "output decrypted file"
            ),

            file2   = arg_filen(
                    NULL, NULL, "<file>", 1, 1,
                    "input encrypted file"
            ),

            fkey2    = arg_filen(
                    "k", NULL, "<file>", 1, 1,
                    "file containing key"
            ),

            end2   = arg_end(8)
    };

    void *argtable3[] = {
            help3 = arg_lit0(
                    NULL,"help",
                    "print this help and exit"
            ),

            vers3 = arg_lit0(
                    NULL,"version",
                    "print version information and exit"
            ),

            end2   = arg_end(20)
    };

    char progname[] = "catastrophic-aes";
    int exitcode = 0;

    if (arg_nullcheck(argtable1)!=0 ||
        arg_nullcheck(argtable2)!=0 ||
        arg_nullcheck(argtable3)!=0)
    {
        /* NULL entries were detected, some allocations must have failed */
        printf("%s: insufficient memory\n",progname);
        exitcode=1;
        goto exit;
    }

    /* Above we defined a separate argtable for each possible command line syntax */
    /* and here we parse each one in turn to see if any of them are successful    */
    nerrors1 = arg_parse(argc, argv, argtable1);
    nerrors2 = arg_parse(argc, argv, argtable2);
    nerrors3 = arg_parse(argc, argv, argtable3);


    if (nerrors1 == 0)
        exitcode = mainprocedure_encryption(
                verb1->count, help1->count, vers1->count);
    else if (nerrors2 == 0)
        exitcode = mainprocedure_decryption();
    else if (nerrors3)
        exitcode = mainprocedure_help()

    if (cmd1->count > 0)
    {
        /* encryption args correct, so presume decryption syntax was intended
         * target */
        arg_print_errors(stdout, end1, progname);
        printf("usage: %s ", progname);
        arg_print_syntax(stdout, argtable1,"\n");
    }
    else if (cmd2->count > 0)
    {
        /* decrpytion args correct, so presume decryption syntax was intended
         * target */
        arg_print_errors(stdout, end2, progname);
        printf("usage: %s ", progname);
        arg_print_syntax(stdout, argtable2, "\n");
    }
    else
    {
        /* no correct cmd literals were given */
        printf("%s: missing encryption | decryption | help command.\n",
                progname);
        printf("usage 1: %s ", progname);
        arg_print_syntax(stdout, argtable1, "\n");
        printf("usage 2: %s ", progname);
        arg_print_syntax(stdout, argtable2, "\n");
        printf("usage 3: %s ", progname);
        arg_print_syntax(stdout, argtable3, "\n");
    }

    exit:
    /* deallocate each non-null entry in argtable[] */
    arg_freetable(argtable1, sizeof(argtable1) / sizeof(argtable1[0]));
    arg_freetable(argtable2, sizeof(argtable2) / sizeof(argtable2[0]));
    return exitcode;
}
