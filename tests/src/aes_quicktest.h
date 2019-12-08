////
//// Created by roland on 2019-11-19.
////
//
//#ifndef CATASTROPHIC_AES_AES_QUICKTEST_H
//#define CATASTROPHIC_AES_AES_QUICKTEST_H
//
//#include <stdio.h>
//#include <stdlib.h>
//
//#include "../../catastrophic-aes/fileop.h"
//#include "../../utils/stdprojutils.h"
//
//#define PATH "/home/roland/CLionProjects/catastrophic-aes/tests/files"
//
//
//// todo: Extremely provisional test. Implement better tests in near future.
//int
//aes_main_test(uint8_t *key_b)
//{
//    aes_core_ctx_st *ctx = AES_CORE_ctx_init(key_b, KEY128);
//    FILE *fp_plain = fopen(PATH"/test_file.jpg", "rb");
//    FILE *fp_encrypted = fopen(PATH"/test_file.crypt", "wb");
//    NP_CHECK(fp_plain)
//    NP_CHECK(fp_encrypted)
//
//    AES_FILEOP_encrypt_file(fp_plain, fp_encrypted, CBC, ctx);
//
//    fclose(fp_plain);
//    fclose(fp_encrypted);
//
//    fp_encrypted = fopen(PATH"/test_file.crypt", "rb");
//    FILE *fp_decrypted = fopen(PATH"/test_file2.jpg", "wb");
//    NP_CHECK(fp_encrypted)
//    NP_CHECK(fp_decrypted)
//
//    AES_FILEOP_decrypt_file(fp_encrypted, fp_decrypted, ctx);
//
//    fclose(fp_encrypted);
//    fclose(fp_decrypted);
//
//    AES_CORE_ctx_destroy(ctx);
//    return 1;
//}
//
//#endif //CATASTROPHIC_AES_AES_QUICKTEST_H
