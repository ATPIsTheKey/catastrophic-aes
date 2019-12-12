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


aes_fileop_ctx_st*
AES_FILEOP_filecrypt_ctx_init(
        input_buff_st *inpw, uint16_t opmode_magic, uint16_t key_bitlen)
{
    aes_fileop_ctx_st *new_ctx = malloc(sizeof(aes_fileop_ctx_st));
    new_ctx->opmode_magic = opmode_magic;

    new_ctx->key_vec = calloc(key_bitlen / NBITS_BYTE, sizeof(uint8_t));
    NP_CHECK(new_ctx->key_vec)
    new_ctx->key_bitlen = key_bitlen;

    new_ctx->salt_vec = calloc(key_bitlen / NBITS_BYTE, sizeof(uint8_t));
    NP_CHECK(new_ctx->salt_vec)
    new_ctx->salt_len = key_bitlen / NBITS_BYTE;

    if(RAND_bytes(new_ctx->salt_vec, key_bitlen / NBITS_BYTE) != 1)
        return NULL;

    if (PKCS5_PBKDF2_HMAC_SHA1(
            inpw->b, inpw->len,
            new_ctx->salt_vec, new_ctx->salt_len,
            NITERS_PWHASH, key_bitlen / NBITS_BYTE,
            new_ctx->key_vec
            ) != 1 )
        return NULL;

    return new_ctx;
}


void
AES_FILEOP_filecrypt_ctx_destroy(aes_fileop_ctx_st *ctx)
{
    free(ctx->key_vec);
    free(ctx->salt_vec);
    free(ctx);
}


static int
prepare_aes_fheader(aes_fheader_st *fheader, aes_fileop_ctx_st *ctx)
{
    fheader->opmode_magic = ctx->opmode_magic;

    // Fill with null bytes initially as keylen not necessarily 32 bytes.
    memset(fheader->salt_vec, 0x00, NBYTES_SALTVEC);
    memcpy(fheader->salt_vec, ctx->salt_vec, ctx->salt_len);
    fheader->key_salt_len     = ctx->salt_len;

    // Generate random initialization vector
    if (ctx->opmode_magic != ECB)
        if (RAND_bytes(fheader->init_vec, NBYTES_INITVEC) != 1)
            return -1;

    return 0;
}


int
fread_aes_fheader(aes_fheader_st *fheader, FILE *fp)
{
    fread(&fheader->opmode_magic, 1, NBYTES_OPMAGIC, fp);
    fread(&fheader->init_vec, 1, NBYTES_INITVEC, fp);

    fread(&fheader->key_salt_len, 1, sizeof(uint16_t), fp);
    fread(&fheader->salt_vec, 1, NBYTES_SALTVEC, fp);

    return 0;
}


/*
 * The function xor_buff XORs two buffers of identical length b_len.
 */

static void
xor_buff(uint8_t *a, const uint8_t *b, size_t b_len)
{
    for (size_t i = 0; i < b_len; i++)
        a[i] ^= b[i];
}


/*
 * The function ECB_encrypt_file makes an encrypted copy of the file in
 * Electronic Codebook (ECB) mode.
 * The file is divided into 16 byte blocks, and each block is encrypted
 * separately.
 * There is a significant lack of diffusion in the final encrypted file, hence
 * this mode lacks serious message confidentiality, and it is not recommended
 * for use in cryptographic protocols at all.
 */

static int
ECB_encrypt_file(FILE *fp_in, FILE *fp_out, aes_fileop_ctx_st *ctx)
{
    uint8_t plain_b[16], enc_b[16];
    size_t b_read = 0;

    // Initialize and write file header
    aes_fheader_st fheader;
    prepare_aes_fheader(&fheader, ctx);
    fwrite(&fheader, sizeof(aes_fheader_st), 1, fp_out);

    // Initialize AES_CORE context from FILEOP context
    aes_core_ctx_st *core_ctx = AES_CORE_ctx_init(ctx->key_vec, ctx->key_bitlen);

    // Begin file encryption
    while ((b_read = fread(plain_b, 1, sizeof(plain_b), fp_in)) == 16)
    {
        AES_CORE_cipher_block(plain_b, enc_b, core_ctx);
        fwrite(enc_b, sizeof(uint8_t), NBYTES_STATE, fp_out);
    }

    // If the last plaintext block is not a multiple of 16 bytes, pad it with
    // null bytes
    if (b_read) {
        for (size_t i = b_read; i < 16; i++)
            plain_b[i] = 0x00;

        // Repeat encryption procedure for last plaintext block
        AES_CORE_cipher_block(plain_b, enc_b, core_ctx);
        fwrite(enc_b, sizeof(uint8_t), NBYTES_STATE, fp_out);
    }

    AES_CORE_ctx_destroy(core_ctx);
    return 0;
}


/*
 * The function ECB_decrypt_file makes a decrypted copy of the ECB
 * encrypted file. The file is divided into 16 byte blocks, and each block is
 * decrypted separately.
 */

static int
ECB_decrypt_file(FILE *fp_in, FILE *fp_out,
                 aes_fheader_st *fheader, input_buff_st *inpw)
{
    uint8_t enc_b[16], plain_b[16];
    uint8_t pw_key_b[fheader->key_salt_len];

    if (PKCS5_PBKDF2_HMAC_SHA1(
            inpw->b, inpw->len,
            fheader->salt_vec,
            fheader->key_salt_len,
            NITERS_PWHASH, fheader->key_salt_len, pw_key_b
            ) != 1 )
        return -1;

    aes_core_ctx_st *core_ctx = AES_CORE_ctx_init(
            pw_key_b, fheader->key_salt_len * NBITS_BYTE);

    while (fread(enc_b, sizeof(enc_b), 1, fp_in))
    {
        AES_CORE_invcipher_block(enc_b, plain_b, core_ctx);
        fwrite(plain_b, sizeof(uint8_t), NBYTES_STATE, fp_out);
    }

    AES_CORE_ctx_destroy(core_ctx);
    return 0;
}



/*
 * The function CBC_encrypt_file makes an encrypted copy of the file in
 * Cipher Block Chaining (CBC) mode.
 * The file is encrypted by sequentially encrypting 16 byte blocks of
 * plaintext where the plaintext is XORed with the previous ciphertext block before
 * being encrypted.
 * To make each message unique, a random 16 byte initialization vector is used
 * for the first plaintext block.
 * This initialization vector is stored in the beginning of the file at an
 * offset of 5 bytes.
 */

static int
CBC_encrypt_file(FILE *fp_in, FILE *fp_out, aes_fileop_ctx_st *ctx)
{
    uint8_t plain_b[16], enc_b[16];
    size_t b_read = 0;

    // Initialize and write file header
    aes_fheader_st fheader;
    prepare_aes_fheader(&fheader, ctx);
    fwrite(&fheader, sizeof(aes_fheader_st), 1, fp_out);

    // For convenience during first state encryption, set enc_b buffer
    // initially to init_vec
    memcpy(enc_b, fheader.init_vec, NBYTES_STATE);

    // Initialize AES_CORE context from FILEOP context
    aes_core_ctx_st *core_ctx = AES_CORE_ctx_init(ctx->key_vec, ctx->key_bitlen);

    // Begin file encryption
    while ((b_read = fread(plain_b, 1, sizeof(plain_b), fp_in)) == 16)
    {
        // The plaintext buffer is XORed with the previous encrypted bytes
        // buffer.
        xor_buff(plain_b, enc_b, NBYTES_STATE);
        AES_CORE_cipher_block(plain_b, enc_b, core_ctx);
        fwrite(enc_b, sizeof(uint8_t), NBYTES_STATE, fp_out);
    }

    // If the last plaintext block is not a multiple of 16 bytes, pad it with
    // null bytes
    if (b_read) {
        for (; b_read < 16; b_read++)
            plain_b[b_read] = 0x00;

        // Repeat encryption procedure for last plaintext block
        xor_buff(plain_b, enc_b, NBYTES_STATE);
        AES_CORE_cipher_block(plain_b, enc_b, core_ctx);
        fwrite(enc_b, sizeof(uint8_t), NBYTES_STATE, fp_out);
    }

    return 0;
}


/*
 * The function CBC_decrypt_file makes a decrypted copy of the CBC
 * encrypted file.
 * Each 16 byte ciphertext block of the encrypted file is XORed with the
 * ciphertext of the previous block.
 * To decrypt the first byte block the initialization vector is required,
 * which is pointed to by *init_vec.
 */

static int
CBC_decrypt_file(FILE *fp_in, FILE *fp_out,
                 aes_fheader_st *fheader, input_buff_st *inpw)
{
    uint8_t enc_b[16], plain_b[16], enc_b_prev[16];
    uint8_t pw_key_b[fheader->key_salt_len];

    if (PKCS5_PBKDF2_HMAC_SHA1(
            inpw->b, inpw->len,
            fheader->salt_vec,
            fheader->key_salt_len,
            NITERS_PWHASH, fheader->key_salt_len, pw_key_b
            ) != 1 )
        return -1;


    // For convenience, copy the initialization vector into enc_b_prev buffer
    // for first ciphertext XORing
    memcpy(enc_b_prev, fheader->init_vec, NBYTES_STATE * sizeof(uint8_t));

    aes_core_ctx_st *core_ctx = AES_CORE_ctx_init(
            pw_key_b, fheader->key_salt_len * NBITS_BYTE);

    while (fread(enc_b, 1, sizeof(enc_b), fp_in))
    {
        AES_CORE_invcipher_block(enc_b, plain_b, core_ctx);
        xor_buff(plain_b, enc_b_prev, NBYTES_STATE);
        fwrite(plain_b, sizeof(uint8_t), NBYTES_STATE, fp_out);
        memcpy(enc_b_prev, enc_b, NBYTES_STATE);
    }

    return 0;
}


/*
 * The function CTR_encrypt_file makes a encrypted copy of the file in
 * Counter mode (CTR).
 * CTR mode turns the AES block cipher to a stream cipher in that it
 * generates the next keystream block by encrypting successive values of a
 * "counter".
 * In this implementation the counter is a 64 bit integer that is incremented
 * per ciphered 16 byte plain message block of the file.
 * A random 64 bit (8 byte) nonce value is concatenated with the counter to
 * produce a unique counter block for every encryption.
 */

static int
CTR_encrypt_file(FILE *fp_in, FILE *fp_out, aes_fileop_ctx_st *ctx)
{
    uint8_t plain_b[16], enc_b[16];
    // nonce_ctr buffer holds nonce bytes and counter
    uint64_t nonce_ctr[2] = {0x00, 0x00};
    size_t b_read = 0;

    aes_fheader_st fheader;
    prepare_aes_fheader(&fheader, ctx);
    fwrite(&fheader, sizeof(aes_fheader_st), sizeof(uint8_t), fp_out);

    // For convenience during first plaintext ciphering, copy initialization
    // vector into nonce_ctr buffer
    memcpy(nonce_ctr, fheader.init_vec, NBYTES_NONCE);

    // Initialize AES_CORE context from FILEOP context
    aes_core_ctx_st *core_ctx = AES_CORE_ctx_init(ctx->key_vec, ctx->key_bitlen);

    // Begin file encryption
    while ((b_read = fread(plain_b, 1, sizeof(plain_b), fp_in)) == 16)
    {
        AES_CORE_cipher_block( (uint8_t*) nonce_ctr, enc_b, core_ctx);
        xor_buff(enc_b, plain_b, NBYTES_STATE);
        fwrite(enc_b, sizeof(uint8_t), NBYTES_STATE, fp_out);
        nonce_ctr[1]++; // increment counter
    }

    // If the last plaintext block is not a multiple of 16 bytes, pad it with
    // null bytes
    if (b_read) {
        for (; b_read < 16; b_read++)
            plain_b[b_read] = 0x00;

        // Repeat encryption procedure for last plaintext block
        AES_CORE_cipher_block((uint8_t *) nonce_ctr, enc_b, core_ctx);
        xor_buff(enc_b, plain_b, NBYTES_STATE);
        fwrite(enc_b, sizeof(uint8_t), NBYTES_STATE, fp_out);
    }

    return 0;
}


/*
 * The function AES_CTR_decrypt makes a decrypted copy of the CTR encrypted
 * file.
 * The nonce value from the init vector is concatenated with a 64 bit counter
 * value that is incremented per deciphered 16 byte block of the file.
 * Each block is deciphered by encrypting the counter and then XORing it
 * with the ciphertext block.
 */

static int
AES_CTR_decrypt_file(FILE *fp_in, FILE *fp_out,
                     aes_fheader_st *fheader, input_buff_st *inpw)
{
    uint8_t enc_b[16], plain_b[16];
    uint64_t nonce_ctr[2] = { 0x00, 0x00 };
    uint8_t pw_key_b[fheader->key_salt_len];

    if (PKCS5_PBKDF2_HMAC_SHA1(
            inpw->b, inpw->len,
            fheader->salt_vec,
            fheader->key_salt_len,
            NITERS_PWHASH, fheader->key_salt_len, pw_key_b
            ) != 1 )
        return -1;

    // Copy 8 bytes nonce value of init vector into first 8 bytes of
    // nonce_ctr buffer
    memcpy(nonce_ctr, fheader->init_vec, NBYTES_NONCE);

    aes_core_ctx_st *core_ctx = AES_CORE_ctx_init(
            pw_key_b, fheader->key_salt_len * NBITS_BYTE);

    while (fread(enc_b, 1, sizeof(enc_b), fp_in))
    {
        AES_CORE_cipher_block((uint8_t *) nonce_ctr, plain_b, core_ctx);
        xor_buff(plain_b, enc_b, NBYTES_STATE);
        fwrite(plain_b, NBYTES_STATE * sizeof(uint8_t), 1, fp_out);
        nonce_ctr[1]++;
    }

    return 0;
}


int
AES_FILEOP_encrypt_file(FILE *fp_in, FILE *fp_out, aes_fileop_ctx_st *ctx)
{
    switch (ctx->opmode_magic) {
        case ECB:
            ECB_encrypt_file(fp_in, fp_out, ctx);
            break;

        case CBC:
            CBC_encrypt_file(fp_in, fp_out, ctx);
            break;

        case CTR:
            CTR_encrypt_file(fp_in, fp_out, ctx);
            break;

        default:
            return -1; // todo: handle error in encryption mode
    }

    return 0;
}


int
AES_FILEOP_decrypt_file(FILE *fp_in, FILE *fp_out, input_buff_st *inpw)
{
    aes_fheader_st fheader;
    fread_aes_fheader(&fheader, fp_in);

    switch (fheader.opmode_magic) {
        case ECB:
            ECB_decrypt_file(fp_in, fp_out, &fheader, inpw);
            break;

        case CBC:
            CBC_decrypt_file(fp_in, fp_out, &fheader, inpw);
            break;

        case CTR:
            AES_CTR_decrypt_file(fp_in, fp_out, &fheader, inpw);
            break;

        default:
            return -1; // todo: handle error encryption mode
    }

    return 0;
}