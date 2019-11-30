//
// Created by roland on 2019-11-15.
//

#include <stdio.h>
#include <string.h>

#include <openssl/rand.h>

#include "core.h"
#include "fcrypt.h"

#define NBYTES_STATE   16
#define NBYTES_SALTVEC 32
#define NBYTES_INITVEC 16
#define NBYTES_NONCE   8
#define NBYTES_WORD    4


/*
 * The function xor_buff XORs two buffers of identical length b_len.
 */

static void
xor_buff(uint8_t *a, const uint8_t *b, size_t b_len)
{
    for (size_t i = 0; i < b_len; i++)
        a[i] ^= b[i];
}


static int
AES_fheader_prepare(
        aes_fheader_s *fheader, uint16_t opmode_magic, aes_ctx_s *ctx)
{
    fheader->opmode_magic = opmode_magic;
    fheader->salt_len     = ctx->key->Nb * NBYTES_WORD;

    switch (opmode_magic) {
        case ECB:
            // In ECB mode, no initialization vector is used. Thus, fill it
            // with null bytes.
            memset(fheader->init_vector, '\0', NBYTES_INITVEC);
            break;

        case CBC:
            // Generate random 16 bytes initialization vector.
            if (RAND_bytes(fheader->init_vector, NBYTES_INITVEC) != 1)
                return -1;

            // Number of salt bytes depends on number of words per key.
            fheader->salt_len = ctx->key->Nb * NBYTES_WORD;

            // Fill salt vector with null bytes, as it might not be fully
            // filled depending on key length.
            memset(fheader->salt_vector, '\0', NBYTES_SALTVEC);

            // Generate random Nb * 4 salt bytes
            if (RAND_bytes(fheader->salt_vector, fheader->salt_len) != 1)
                return -1;
            break;

        case CTR:
            // Fill 16 bytes initialization vector with null bytes as nonce
            // value is only 8 bytes.
            memset(fheader->init_vector, '\0', NBYTES_INITVEC);

            // In CTR mode, initialization vector is used to hold 8 byte nonce
            // value.
            if (RAND_bytes(fheader->init_vector, NBYTES_NONCE) != 1)
                return -1;

            // Fill salt vector with null bytes, as it might not be fully
            // filled depending on key length.
            memset(fheader->salt_vector, '\0', NBYTES_SALTVEC);

            // Generate random Nb * 4 salt bytes.
            if (RAND_bytes(fheader->salt_vector, fheader->salt_len) != 1)
                return -1;
            break;

        case CFB:
            break;

        case OFB:
            break;

        default:
            return -1;
    }

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

static int
AES_ECB_encrypt_file(FILE *fp_in, FILE *fp_out, aes_ctx_s *ctx)
{
    uint8_t plain_b[16], enc_b[16];
    size_t b_read = 0;

    aes_fheader_s fheader;
    AES_fheader_prepare(&fheader, ECB, ctx);

    fwrite(&fheader, sizeof(aes_fheader_s), sizeof(uint8_t), fp_out);
    while ((b_read = fread(plain_b, 1, sizeof(plain_b), fp_in)) == 16) {
        AES_cipher_block(plain_b, enc_b, ctx);
        fwrite(enc_b, NBYTES_STATE * sizeof(uint8_t), 1, fp_out);
    }

    // If the last plaintext block is not a multiple of 16 bytes, pad it with
    // null bytes
    if (b_read) {
        for (size_t i = b_read; i < 16; i++)
            plain_b[i] = '\0';
        // repeat encryption procedure for last plaintext block
        AES_cipher_block(plain_b, enc_b, ctx);
        fwrite(enc_b, NBYTES_STATE * sizeof(uint8_t), 1, fp_out);
    }

    return 1;
}


/*
 * The function AES_ECB_decrypt_file makes a decrypted copy of the ECB
 * encrypted file. The file is divided into 16 byte blocks, and each block is
 * decrypted separately.
 */

static int
AES_ECB_decrypt_file(FILE *fp_in, FILE *fp_out, const aes_ctx_s *ctx)
{
    uint8_t enc_b[16], plain_b[16];

    while (fread(enc_b, 1, sizeof(enc_b), fp_in))
    {
        AES_invcipher_block(enc_b, plain_b, ctx);
        fwrite(plain_b, NBYTES_STATE * sizeof(uint8_t), 1, fp_out);
    }

    return 1;
}


/*
 * The function AES_CBC_encrypt_file makes an encrypted copy of the file in
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
AES_CBC_encrypt_file(FILE *fp_in, FILE *fp_out, aes_ctx_s *ctx)
{
    uint8_t plain_b[16], enc_b[16];
    size_t b_read = 0;

    aes_fheader_s fheader;
    AES_fheader_prepare(&fheader, ECB, ctx);

    fwrite(&fheader, sizeof(aes_fheader_s), sizeof(uint8_t), fp_out);
    while ((b_read = fread(plain_b, 1, sizeof(plain_b), fp_in)) == 16)
    {
        // The plaintext buffer is XORed with the previous encrypted bytes
        // buffer.
        xor_buff(plain_b, enc_b, NBYTES_STATE);
        AES_cipher_block(plain_b, enc_b, ctx);
        fwrite(enc_b, NBYTES_STATE * sizeof(uint8_t), 1, fp_out);
    }

    // If the last plaintext block is not a multiple of 16 bytes, pad it with
    // null bytes
    if (b_read) {
        for (; b_read < 16; b_read++)
            plain_b[b_read] = '\0';
        // repeat encryption procedure for last plaintext block
        xor_buff(plain_b, enc_b, NBYTES_STATE);
        AES_cipher_block(plain_b, enc_b, ctx);
        fwrite(enc_b, NBYTES_STATE * sizeof(uint8_t), 1, fp_out);
    }

    return 1;
}


/*
 * The function aes_CBC_decrypt_file makes a decrypted copy of the CBC
 * encrypted file.
 * Each 16 byte ciphertext block of the encrypted file is XORed with the
 * ciphertext of the previous block.
 * To decrypt the first byte block the initialization vector is required,
 * which is pointed to by *init_vector.
 */

static int
aes_CBC_decrypt_file(
        FILE *fp_in, FILE *fp_out, const aes_ctx_s *ctx, const uint8_t *init_vector)
{
    uint8_t enc_b[16], plain_b[16], enc_b_prev[16];
    // for convenience, copy the initialization vector into enc_b_prev buffer
    // for first ciphertext XORing
    memcpy(enc_b_prev, init_vector, NBYTES_STATE * sizeof(uint8_t));

    while (fread(enc_b, 1, sizeof(enc_b), fp_in)) {
        AES_invcipher_block(enc_b, plain_b, ctx);
        xor_buff(plain_b, enc_b_prev, NBYTES_STATE);
        fwrite(plain_b, NBYTES_STATE * sizeof(uint8_t), 1, fp_out);
        memcpy(enc_b_prev, enc_b, NBYTES_STATE);
    }

    return 1;
}


/*
 * The function AES_CTR_encrypt makes a encrypted copy of the file in
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
AES_CTR_encrypt(FILE *fp_in, FILE *fp_out, aes_ctx_s *ctx)
{
    uint8_t plain_b[16], enc_b[16];
    // nonce_ctr buffer holds nonce bytes and counter
    uint64_t nonce_ctr[2];
    size_t b_read = 0;

    aes_fheader_s fheader;
    AES_fheader_prepare(&fheader, ECB, ctx);

    fwrite(&fheader, sizeof(aes_fheader_s), sizeof(uint8_t), fp_out);

    // For convenience during first plaintext ciphering, copy initialization
    // vector into nonce_ctr buffer
    memcpy(nonce_ctr, fheader.init_vector, NBYTES_INITVEC);
    while ((b_read = fread(plain_b, 1, sizeof(plain_b), fp_in)) == 16)
    {
        AES_cipher_block((uint8_t *) nonce_ctr, enc_b, ctx);
        xor_buff(enc_b, plain_b, NBYTES_STATE);
        fwrite(enc_b, NBYTES_STATE * sizeof(uint8_t), 1, fp_out);
        nonce_ctr[1]++; // increment counter
    }

    // If the last plaintext block is not a multiple of 16 bytes, pad it with
    // null bytes
    if (b_read) {
        for (; b_read < 16; b_read++)
            plain_b[b_read] = '\0';

        // repeat encryption procedure for last plaintext block
        AES_cipher_block((uint8_t *) nonce_ctr, enc_b, ctx);
        xor_buff(enc_b, plain_b, NBYTES_STATE);
        fwrite(enc_b, NBYTES_STATE * sizeof(uint8_t), 1, fp_out);
    }

    return 1;
}


/*
 * The function aes_CTR_decrypt makes a decrypted copy of the CTR encrypted
 * file.
 * The nonce value from the init vector is concatenated with a 64 bit counter
 * value that is incremented per deciphered 16 byte block of the file.
 * Each block is deciphered by encrypting the counter and then XORing it
 * with the ciphertext block.
 */

static int
AES_CTR_decrypt_file(
        FILE *fp_in, FILE *fp_out, const aes_ctx_s *ctx, const uint8_t *init_vector)
{
    uint8_t enc_b[16], plain_b[16];
    uint64_t nonce_ctr[2] = { 0x00, 0x00 };

    // copy 8 bytes nonce value of init vector into first 8 bytes of nonce_ctr buffer
    memcpy((uint8_t*) nonce_ctr, init_vector, 2 * sizeof(uint64_t));

    while (fread(enc_b, 1, sizeof(enc_b), fp_in))
    {
        AES_cipher_block((uint8_t *) nonce_ctr, plain_b, ctx);
        xor_buff(plain_b, enc_b, NBYTES_STATE);
        fwrite(plain_b, NBYTES_STATE * sizeof(uint8_t), 1, fp_out);
        nonce_ctr[1]++;
    }

    return 1;
}


int
AES_encrypt_file(
        FILE *fp_in, FILE *fp_out, uint16_t opmode_magic, const aes_ctx_s *ctx)
{
    switch (opmode_magic) {
        case ECB:
            AES_ECB_encrypt_file(fp_in, fp_out, ctx);
            break;

        case CBC:
            AES_CBC_encrypt_file(fp_in, fp_out, ctx);
            break;

        case CFB:
            break;

        case OFB:
            break;

        case CTR:
            AES_CTR_encrypt(fp_in, fp_out, ctx);
            break;

        default:
            return -1;
    }

    return 0;
}


int
AES_file_decrypt(FILE *fp_in, FILE *fp_out, const aes_ctx_s *ctx)
{
    uint16_t opmode_magic;
    fread(&opmode_magic, sizeof(opmode_magic), 1, fp_in);

    uint8_t init_vector[16];
    fread(init_vector, sizeof(init_vector), 1, fp_in);

    switch (opmode_magic) {
        case ECB:
            AES_ECB_decrypt_file(fp_in, fp_out, ctx);
            break;

        case CBC:
            aes_CBC_decrypt_file(fp_in, fp_out, ctx, init_vector);
            break;

        case CFB:
            break;

        case OFB:
            break;

        case CTR:
            AES_CTR_decrypt_file(fp_in, fp_out, ctx, init_vector);
            break;

         default:
            return -1;
    }

    return 0;
}
