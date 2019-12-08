//
// Created by roland on 2019-11-15.
//

#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "core.h"
#include "fileop.h"
#include "../utils/stdprojutils.h"
#include "utils.h"

#define NBYTES_STATE   16
#define NBYTES_SALTVEC 32
#define NBYTES_INITVEC 16
#define NBYTES_NONCE   8
#define NBYTES_WORD    4
#define NBITS_BYTE     8
#define NITERS_PWHASH  1000
#define NBYTES_OPMAGIC 2

/*
 * The function xor_buff XORs two buffers of identical length b_len.
 */

static void
xor_buff(uint8_t *a, const uint8_t *b, size_t b_len)
{
    for (size_t i = 0; i < b_len; i++)
        a[i] ^= b[i];
}


aes_fcrypt_ctx_st*
AES_FILEOP_filecrypt_ctx_init(
        input_buff_st *inpw, uint16_t opmode_magic, uint16_t key_bitlen)
{
    aes_fcrypt_ctx_st *new_ctx = malloc(sizeof(aes_fcrypt_ctx_st));
    new_ctx->opmode_magic = opmode_magic;

    new_ctx->bkey = calloc(key_bitlen / NBITS_BYTE, sizeof(uint8_t));
    NP_CHECK(new_ctx->bkey)
    new_ctx->key_bitlen = key_bitlen;

    new_ctx->salt = calloc(key_bitlen / NBITS_BYTE, sizeof(uint8_t));
    NP_CHECK(new_ctx->salt)
    new_ctx->salt_len = key_bitlen / NBITS_BYTE;

    if(RAND_bytes(new_ctx->salt, key_bitlen / NBITS_BYTE) != 1)
        return NULL;

    if (PKCS5_PBKDF2_HMAC_SHA1(
            inpw->b, inpw->len, new_ctx->salt, new_ctx->salt_len,
            NITERS_PWHASH, key_bitlen / NBITS_BYTE, new_ctx->bkey
            ) != 1 )
        return NULL;

    return new_ctx;
}


void
AES_FILEOP_filecrypt_ctx_destroy(aes_fcrypt_ctx_st *ctx)
{
    free(ctx->bkey);
    free(ctx->salt);
    free(ctx);
}


int
AES_FILEOP_prepare_fheader(aes_fheader_st *fheader, aes_fcrypt_ctx_st *ctx)
{
    fheader->opmode_magic = ctx->opmode_magic;

    // Fill with null bytes initially as keylen not necessarily 32 bytes.
    memset(fheader->salt_vector, 0x00, NBYTES_SALTVEC);
    memcpy(fheader->salt_vector, ctx->salt, ctx->salt_len);
    fheader->salt_len     = ctx->salt_len;

    // Generate random 16 bytes initialization vector.
    if (ctx->opmode_magic != ECB)
        if (RAND_bytes(fheader->init_vector, NBYTES_INITVEC) != 1)
            return -1;

    return 0;
}


int
AES_FILEOP_fread_fheader(aes_fheader_st *fheader, FILE *fp)
{
    fread(&fheader->opmode_magic, 1, NBYTES_OPMAGIC, fp);
    fread(&fheader->init_vector,  1, NBYTES_INITVEC, fp);

    fread(&fheader->salt_len,     1, sizeof(uint16_t), fp);
    fread(&fheader->salt_vector,  1, NBYTES_SALTVEC, fp);

    return 0;
}


/*
 * The function AES_ECB_encrypt_file makes an encrypted copy of the file in
 * Electronic Codebook (ECB) mode.
 * The file is divided into 16 byte blocks, and each block is encrypted
 * separately.
 * There is a significant lack of diffusion in the final encrypted file, hence
 * this mode lacks serious message confidentiality, and it is not recommended
 * for use in cryptographic protocols at all.
 */

int
AES_ECB_encrypt_file(FILE *fp_in, FILE *fp_out, aes_fcrypt_ctx_st *ctx)
{
    uint8_t plain_b[16], enc_b[16];
    size_t b_read = 0;

    aes_fheader_st fheader;
    AES_FILEOP_prepare_fheader(&fheader, ctx);
    fwrite(&fheader, sizeof(aes_fheader_st), 1, fp_out);

    aes_core_ctx_st *core_ctx = AES_CORE_ctx_init(ctx->bkey, ctx->key_bitlen);
    while ((b_read = fread(plain_b, 1, sizeof(plain_b), fp_in)) == 16) {
        AES_CORE_cipher_block(plain_b, enc_b, core_ctx);
        fwrite(enc_b, NBYTES_STATE * sizeof(uint8_t), 1, fp_out);
    }

    // If the last plaintext block is not a multiple of 16 bytes, pad it with
    // null bytes
    if (b_read) {
        for (size_t i = b_read; i < 16; i++)
            plain_b[i] = 0x00;
        // repeat encryption procedure for last plaintext block
        AES_CORE_cipher_block(plain_b, enc_b, core_ctx);
        fwrite(enc_b, NBYTES_STATE * sizeof(uint8_t), 1, fp_out);
    }

    AES_CORE_ctx_destroy(core_ctx);
    return 0;
}


/*
 * The function AES_ECB_decrypt_file makes a decrypted copy of the ECB
 * encrypted file. The file is divided into 16 byte blocks, and each block is
 * decrypted separately.
 */

int
AES_ECB_decrypt_file(FILE *fp_in, FILE *fp_out, aes_fdecrypt_ctx_st *ctx)
{
    aes_fheader_st fheader;
    AES_FILEOP_fread_fheader(&fheader, fp_in);

    uint8_t enc_b[16], plain_b[16];
    uint8_t pw_bkey[fheader.salt_len]; // Salt length equivalent to key length
    // todo: indicate aes mode in file header

    if (PKCS5_PBKDF2_HMAC_SHA1(
            ctx->inpw->b, ctx->inpw->len, fheader.salt_vector, fheader.salt_len,
            NITERS_PWHASH, fheader.salt_len, pw_bkey // Salt length equivalent to key length
        ) != 1 )
        return -1;

    aes_core_ctx_st *core_ctx = AES_CORE_ctx_init(pw_bkey, fheader.salt_len);
    while (fread(enc_b, sizeof(enc_b), 1, fp_in))
    {
        AES_CORE_invcipher_block(enc_b, plain_b, core_ctx);
        fwrite(plain_b, NBYTES_STATE * sizeof(uint8_t), 1, fp_out);
    }

    AES_CORE_ctx_destroy(core_ctx);
    return 0;
}

//
//
///*
// * The function AES_CBC_encrypt_file makes an encrypted copy of the file in
// * Cipher Block Chaining (CBC) mode.
// * The file is encrypted by sequentially encrypting 16 byte blocks of
// * plaintext where the plaintext is XORed with the previous ciphertext block before
// * being encrypted.
// * To make each message unique, a random 16 byte initialization vector is used
// * for the first plaintext block.
// * This initialization vector is stored in the beginning of the file at an
// * offset of 5 bytes.
// */
//
//static int
//AES_CBC_encrypt_file(FILE *fp_in, FILE *fp_out, aes_fileop_ctx *ctx)
//{
//    uint8_t plain_b[16], enc_b[16];
//    size_t b_read = 0;
//
//    aes_fheader_st fheader;
//    AES_fheader_prepare(&fheader, ECB, ctx);
//
//    fwrite(&fheader, sizeof(aes_fheader_st), sizeof(uint8_t), fp_out);
//    while ((b_read = fread(plain_b, 1, sizeof(plain_b), fp_in)) == 16)
//    {
//        // The plaintext buffer is XORed with the previous encrypted bytes
//        // buffer.
//        xor_buff(plain_b, enc_b, NBYTES_STATE);
//        AES_CORE_cipher_block(plain_b, enc_b, ctx);
//        fwrite(enc_b, NBYTES_STATE * sizeof(uint8_t), 1, fp_out);
//    }
//
//    // If the last plaintext block is not a multiple of 16 bytes, pad it with
//    // null bytes
//    if (b_read) {
//        for (; b_read < 16; b_read++)
//            plain_b[b_read] = '\0';
//        // repeat encryption procedure for last plaintext block
//        xor_buff(plain_b, enc_b, NBYTES_STATE);
//        AES_CORE_cipher_block(plain_b, enc_b, ctx);
//        fwrite(enc_b, NBYTES_STATE * sizeof(uint8_t), 1, fp_out);
//    }
//
//    return 1;
//}
//
//
///*
// * The function aes_CBC_decrypt_file makes a decrypted copy of the CBC
// * encrypted file.
// * Each 16 byte ciphertext block of the encrypted file is XORed with the
// * ciphertext of the previous block.
// * To decrypt the first byte block the initialization vector is required,
// * which is pointed to by *init_vector.
// */
//
//static int
//aes_CBC_decrypt_file(
//        FILE *fp_in, FILE *fp_out, const aes_fileop_ctx *ctx, const uint8_t *init_vector)
//{
//    uint8_t enc_b[16], plain_b[16], enc_b_prev[16];
//    // for convenience, copy the initialization vector into enc_b_prev buffer
//    // for first ciphertext XORing
//    memcpy(enc_b_prev, init_vector, NBYTES_STATE * sizeof(uint8_t));
//
//    while (fread(enc_b, 1, sizeof(enc_b), fp_in)) {
//        AES_CORE_invcipher_block(enc_b, plain_b, ctx);
//        xor_buff(plain_b, enc_b_prev, NBYTES_STATE);
//        fwrite(plain_b, NBYTES_STATE * sizeof(uint8_t), 1, fp_out);
//        memcpy(enc_b_prev, enc_b, NBYTES_STATE);
//    }
//
//    return 1;
//}
//
//
///*
// * The function AES_CTR_encrypt makes a encrypted copy of the file in
// * Counter mode (CTR).
// * CTR mode turns the AES block cipher to a stream cipher in that it
// * generates the next keystream block by encrypting successive values of a
// * "counter".
// * In this implementation the counter is a 64 bit integer that is incremented
// * per ciphered 16 byte plain message block of the file.
// * A random 64 bit (8 byte) nonce value is concatenated with the counter to
// * produce a unique counter block for every encryption.
// */
//
//static int
//AES_CTR_encrypt(FILE *fp_in, FILE *fp_out, aes_fileop_ctx *ctx)
//{
//    uint8_t plain_b[16], enc_b[16];
//    // nonce_ctr buffer holds nonce bytes and counter
//    uint64_t nonce_ctr[2];
//    size_t b_read = 0;
//
//    aes_fheader_st fheader;
//    AES_fheader_prepare(&fheader, ECB, ctx);
//
//    fwrite(&fheader, sizeof(aes_fheader_st), sizeof(uint8_t), fp_out);
//
//    // For convenience during first plaintext ciphering, copy initialization
//    // vector into nonce_ctr buffer
//    memcpy(nonce_ctr, fheader.init_vector, NBYTES_INITVEC);
//    while ((b_read = fread(plain_b, 1, sizeof(plain_b), fp_in)) == 16)
//    {
//        AES_CORE_cipher_block((uint8_t *) nonce_ctr, enc_b, ctx);
//        xor_buff(enc_b, plain_b, NBYTES_STATE);
//        fwrite(enc_b, NBYTES_STATE * sizeof(uint8_t), 1, fp_out);
//        nonce_ctr[1]++; // increment counter
//    }
//
//    // If the last plaintext block is not a multiple of 16 bytes, pad it with
//    // null bytes
//    if (b_read) {
//        for (; b_read < 16; b_read++)
//            plain_b[b_read] = '\0';
//
//        // repeat encryption procedure for last plaintext block
//        AES_CORE_cipher_block((uint8_t *) nonce_ctr, enc_b, ctx);
//        xor_buff(enc_b, plain_b, NBYTES_STATE);
//        fwrite(enc_b, NBYTES_STATE * sizeof(uint8_t), 1, fp_out);
//    }
//
//    return 1;
//}
//
//
///*
// * The function aes_CTR_decrypt makes a decrypted copy of the CTR encrypted
// * file.
// * The nonce value from the init vector is concatenated with a 64 bit counter
// * value that is incremented per deciphered 16 byte block of the file.
// * Each block is deciphered by encrypting the counter and then XORing it
// * with the ciphertext block.
// */
//
//static int
//AES_CTR_decrypt_file(
//        FILE *fp_in, FILE *fp_out, const aes_fileop_ctx *ctx, const uint8_t *init_vector)
//{
//    uint8_t enc_b[16], plain_b[16];
//    uint64_t nonce_ctr[2] = { 0x00, 0x00 };
//
//    // copy 8 bytes nonce value of init vector into first 8 bytes of nonce_ctr buffer
//    memcpy((uint8_t*) nonce_ctr, init_vector, 2 * sizeof(uint64_t));
//
//    while (fread(enc_b, 1, sizeof(enc_b), fp_in))
//    {
//        AES_CORE_cipher_block((uint8_t *) nonce_ctr, plain_b, ctx);
//        xor_buff(plain_b, enc_b, NBYTES_STATE);
//        fwrite(plain_b, NBYTES_STATE * sizeof(uint8_t), 1, fp_out);
//        nonce_ctr[1]++;
//    }
//
//    return 1;
//}
