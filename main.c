#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/utsname.h>

#include "catastrophic-aes/utils.h"
#include "catastrophic-aes/fileop.h"
#include "utils/stdprojutils.h"

#include "libs/argtable3.h"
#include "tests/src/aes_quicktest.h"


#define PROGNAME "catastrophic-aes"
#define VERSION "1.0.0"

#define REG_EXTENDED 1
#define REG_ICASE (REG_EXTENDED << 1)


/* SYNTAX 1: encrypt */
struct arg_rex *cmd1;
struct arg_str *opmode_magic;
struct arg_lit *verb1, *help1, *vers1;
struct arg_int *klen;
struct arg_file *file1, *o1;
struct arg_end *end1;
int nerrors1;

/* SYNTAX 2: decrypt */
struct arg_rex *cmd2;
struct arg_lit *verb2, *help2, *vers2;
struct arg_file *file2, *o2;
struct arg_end *end2;
int nerrors2;

/* SYNTAX 3: help or version*/
struct arg_lit *help3;
struct arg_lit *vers3;
struct arg_end *end3;
int nerrors3;


static void
print_version(char *progname, char *suffix)
{
    struct utsname name;
    if(uname(&name)) exit(-1);
    printf("%s (%s@%s) "VERSION"\n", progname, name.sysname, name.release);
    printf(KRED"There is NO warranty; not even for MERCHANTABILITY or "
               "FITNESS FOR A PARTICULAR PURPOSE."KNRM);
    printf("%s", suffix);
}


int
mainprocedure_encryption(
        int opmode_cnt, const char *opmode_str,
        int verb_cnt, int help_cnt, int vers_cnt,
        int klen_cnt, const int klen_val, const char *f_in,
        int f_out_cnt, const char *f_out,
        char *progname, void *argtable
)
{
    // help has precedence
    if (help_cnt)
    {
        printf("Usage: %s", progname);
        arg_print_syntax(stdout, argtable, "\n");
        arg_print_glossary(stdout, argtable, "      %-20s %s\n");
        return 0;
    }
    else if (vers_cnt) // version has second highest precedence
    {
        print_version(progname, "\n");
        return 0;
    }

    int keylen = KEY128;
    if (klen_cnt) {
        if (klen_val == KEY128 || klen_val == KEY192 || klen_val == KEY256)
            keylen = klen_val;
        else {
            printf("Unssuported keylength of %d bits. "
                   "Either 128, 192, or 256. Try '%s --help' "
                   "for more detailed information.\n", klen_val, progname
            );
            return 0;
        }
    }

    uint32_t cipher_opmode_magic = CBC;
    if (opmode_magic->count) {
        if (strcmp(opmode_str, "ECB") == 0)
            cipher_opmode_magic = ECB;
        else if (strcmp(opmode_str, "CBC") == 0)
            cipher_opmode_magic = CBC;
        else if (strcmp(opmode_str, "CTR") == 0)
            cipher_opmode_magic = CTR;
        else {
            printf("Unssuported block cipher operation mode of %s. "
                   "Either ECB, CBC, or CTR. Try '%s --help' "
                   "for more detailed information.\n", opmode_str, progname
            );
            return 0;
        }
    }

    FILE *fp_in  = fopen(f_in, "rb");
    FILE *fp_out;

    if (f_out_cnt)
        fp_out = fopen(f_out, "wb+");
    else {
        char fspec_out[strlen(f_in) + strlen(".crypt")];
        if (strlen(f_in) + strlen(".crypt") > PATH_MAX) {
            printf("Path length exceeding %d chars. Encryption terminated.",
                   PATH_MAX);
            return 0;
        }
        snprintf(fspec_out, sizeof(fspec_out), "%s%s", f_in, ".crypt");
        fp_out = fopen(fspec_out, "wb+");
        printf("%s", fspec_out)
    }


    /*** Begin encryption ************************************************/

    fclose(fp_in);
    fclose(fp_out);
    fclose(fp_in);

    return 0;
}

int
mainprocedure_decryption(
        int verb_cnt, int help_cnt, int vers_cnt,
        const char *finput, const char *foutput,
        char *progname, void *argtable
)
{
    // help has precedence
    if (help_cnt) {
        printf("Usage: %s", progname);
        arg_print_syntax(stdout, argtable, "\n");
        arg_print_glossary(stdout, argtable, "      %-20s %s\n");
        return 0;
    } else if (vers_cnt) {// version has second highest precedence
        print_version(progname, "\n");
        return 0;
    }

    return 0;
}

int
mainprocedure_help(int help_cnt, int version_cnt, char *progname,
                   void *argtable1, void *argtable2, void *argtable3)
{
    // help has precedence over version
    if (help_cnt) {
        printf("Usage: %s", progname);
        arg_print_syntax(stdout, argtable1, "\n");
        arg_print_glossary(stdout, argtable1, "      %-20s %s\n");

        printf("\nUsage: %s", progname);
        arg_print_syntax(stdout, argtable2, "\n");
        arg_print_glossary(stdout, argtable2, "      %-20s %s\n");

        printf("\nUsage: %s", progname);
        arg_print_syntax(stdout, argtable3, "\n");
        arg_print_glossary(stdout, argtable3, "      %-20s %s\n");

        return 0;
    }
    if (version_cnt)
        print_version(progname, "\n");
    return 0;
}


int
main(int argc, char **argv)
{
    /*** Initialize arg parser ************************************************/

    /* SYNTAX 1: encrypt */
    void *argtable1[] = {
            cmd1   = arg_rex1(
                    NULL, NULL, "encrypt", NULL, REG_ICASE,
                    "encrypt a file"
            ),
            opmode_magic = arg_strn(
                    NULL, NULL, "<pattern>", 0, 1,
                    "block cipher mode (EBC, CBC, CTR)"
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
            klen = arg_intn(
                    "l", "klen", "<int>", 0, 1,
                    "key length of either 128, 192 or 256 (default is 128)"
            ),
            file1   = arg_filen(
                    NULL, NULL, "<file>", 1, 1,
                    "input file to be encrypted"
            ),
            o1      = arg_filen(
                    "o", NULL, "<file>", 0, 1,
                    "output encrypted file (otional only; "
                    "placed in current dir by default)"
            ),
            end1   = arg_end(20)
    };

    /* SYNTAX 2: decrypt */
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
            file2   = arg_filen(
                    NULL, NULL, "<file>", 1, 1,
                    "input encrypted file"
            ),
            o2      = arg_filen(
                    "o", NULL, "<file>", 0, 1,
                    "output decrypted file"
            ),
            end2   = arg_end(20)
    };

    /* SYNTAX 3: help or version*/
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

    char progname[] = PROGNAME;
    int exitcode = 0;

    if (arg_nullcheck(argtable1) !=0 ||
        arg_nullcheck(argtable2) !=0 ||
        arg_nullcheck(argtable3) != 0)
    {
        /* NULL entries were detected, some allocations must have failed */
        printf("%s: insufficient memory\n", progname);
        exitcode = 1;
        goto exit;
    }

    /* Above we defined a separate argtable for each possible command line syntax */
    /* and here we parse each one in turn to see if any of them are successful    */
    nerrors1 = arg_parse(argc, argv, argtable1);
    nerrors2 = arg_parse(argc, argv, argtable2);
    nerrors3 = arg_parse(argc, argv, argtable3);

    if (nerrors1 == 0) {
        exitcode = mainprocedure_encryption(
                opmode_magic->count, opmode_magic->sval[0],
                verb1->count, help1->count, vers1->count,
                klen->count, klen->ival[0], file1->filename[0],
                o1->count, o1->filename[0],
                progname, argtable1
        );
        goto exit;
    }
    else if (nerrors2 == 0) {
        exitcode = mainprocedure_decryption(
                verb2->count, help2->count, vers2->count,
                file2->filename[0], o2->filename[0],
                progname, argtable2
        );
        goto exit;
    }
    else if (nerrors3 == 0) {
        exitcode = mainprocedure_help(
                help3->count, vers3->count, progname,
                argtable1, argtable2, argtable3
        );
        goto exit;
    }


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
        printf("Try '%s --help' for more detailed information.\n", progname);
    }

    exit:
    /* deallocate each non-null entry in argtable[] */
    arg_freetable(argtable1, sizeof(argtable1) / sizeof(argtable1[0]));
    arg_freetable(argtable2, sizeof(argtable2) / sizeof(argtable2[0]));
    arg_freetable(argtable3, sizeof(argtable3) / sizeof(argtable3[0]));
    return exitcode;
}