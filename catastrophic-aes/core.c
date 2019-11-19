//
// Created by roland on 2019-11-07.
//

/*
 * Implementation of the Advanced Encryption Standard (AES) after specifications of
 * Federal Information Processing Standards Publication 197.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core.h"
#include "../utils/stdprojutils.h"

#define NBYTES_STATE 16
#define NWORDS_STATE 4
#define NBYTES_STATECOLUMN 4
#define NBYTES_EXPKEY128 176
#define NBYTES_EXPKEY192 208
#define NBYTES_EXPKEY256 240


static uint8_t sbox[256] =   {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
        0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
        0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
        0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
        0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
        0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
        0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
        0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
        0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
        0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
        0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
        0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
        0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
        0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
        0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
        0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};


uint8_t invsbox[256] = {
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
        0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
        0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
        0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
        0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
        0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
        0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
        0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
        0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
        0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
        0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
        0x6f, 0xb7 ,0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56 ,0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
        0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd ,0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
        0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
        0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
        0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b ,0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
        0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};


enum shiftrow_idx {
    B00 = 0,  B01 = 5 , B02 = 10, B03 = 15,
    B10 = 4,  B11 = 9 , B12 = 14, B13 = 3 ,
    B20 = 8,  B21 = 13, B22 = 2 , B23 = 7 ,
    B30 = 12, B31 = 1 , B32 = 6 , B33 = 11
};


////////////////////////
/// Private functions //
////////////////////////


/*
 * The function gmul multiplies polynomials modulo the
 * irreducible polynomial m(x) = x^8 + x^4 + x^3 + x + 1.
 * I only know how to multiply in galois fields on paper.
 * I have implemented gmul algorithm according to fips-197,
 * though, I am not fully understanding the math behind it.
 * I will definitely have to spend more time to understand
 * this algorithm deeply.
 */

static uint8_t
gmul(uint8_t a, uint8_t b)
{
    uint8_t p = 0x00;
    uint8_t hi_bit_set;

    for (uint8_t i = 0; i < 8; i++) {
        if (b & (uint8_t) 0x01)
            p ^= a;
        hi_bit_set = a & (uint8_t) 0x80;
        a <<= (uint8_t) 1;
        if (hi_bit_set)
            a ^= (uint8_t) 0x1b;
        b >>= (uint8_t) 1;
    }
    return p;
}


/*
 * The function rotw takes a word [a0, a1, a2, a3] as input, performs a cyclic
 * permutation, and returns the word [a1, a2, a3, a0].
 */

static void
rotw(uint8_t *w)
{
    uint8_t tmp = w[0];
    w[0] = w[1]; w[1] = w[2]; w[2] = w[3]; w[3] = tmp;
}


/*
 * The function subw substitutes sub-bytes of a word with values of the sbox.
 */

static void
subw(uint8_t *w)
{
    for (uint8_t i = 0; i < NBYTES_STATECOLUMN; i++)
        w[i] = sbox[w[i]];
}


/*
 * The function rcon computes the round constant c which is {02} exponentiated
 * to exponent i in Rijndael's Galois field.
 */

static uint8_t
rcon(uint8_t i)
{
    uint8_t c = 0x01;
    if (i == 0)
        return 0;
    while (i != 1) {
        c = gmul(c, 0x02);
        i--;
    }
    return c;
}


/*
 * The function keysched_core performs the functions rotw and subw on a input
 * word, as well as XORS the first sub-byte of the word with a round constant
 * computed with rcon from i
 */

static void
keysched_core(uint8_t *w, uint8_t i)
{
    rotw(w);
    subw(w);
    w[0] ^= rcon(i);
}


///////////////////////
/// Public functions //
///////////////////////


/*
 * The function expand_key implements the Rindael key schedule to derive
 * Nb(Nr+1) round keys from a single key of length 128 bits, 192 bits or 256 bits.
 * The round keys are used in each round to encrypt/decrypt the states.
 */

void
expand_key(aes_key_s *key, uint8_t *w)
{
    uint8_t tmp[NBYTES_STATECOLUMN]; // used for column and row operations
    uint32_t i = 0;
    uint8_t k = 0;

    // The first round key is the key itself.
    for (; i < key->Nk; i++) {
        for (; k < NBYTES_STATECOLUMN; k++)
            w[i * 4 + k] = key->b[i * 4 + k];
        k = 0;
    }

    // All other round keys are found from the previous round keys.
    for (i = key->Nk; i < key->Nb * (key->Nr + 1); i++) {
        // copy w[i - 1]
        for (k = 0; k < NBYTES_STATECOLUMN; k++)
            tmp[k] = w[i * 4 + k - 4];

        // For words in positions that are a multiple of Nk, keysched_core
        // transformation is applied to w[i - 1] prior to the XOR, followed by
        // an XOR with a round constant, Rcon[i]
        if (i % key->Nk == 0)
            keysched_core(tmp, i / key->Nk);

        // If Nk = 8 and i is a multiple of Nk, then subw operation is
        // applied to w[i - 1] prior to the XOR.
        else if (key->Nk > 6 && i % key->Nk == 4)
            subw(tmp);

        // Every following word, w[i], is equal to the XOR of the
        // previous word, w[i - 1]
        for (k = 0; k < NBYTES_STATECOLUMN; k++)
            w[i * 4 + k] = w[4 * (i - key->Nk) + k] ^ tmp[k];
    }
}


/*
 * The function sub_bytes substitutes the values in the state matrix with values of
 * the sbox.
 */

void
sub_bytes(uint8_t *state)
{
    for (uint8_t i = 0; i < NBYTES_STATE; i++)
        state[i] = sbox[state[i]];
}


/*
 * The function sub_bytes substitutes the values in the state matrix with values of
 * the inverse sbox.
 */

void
inv_sub_bytes(uint8_t *state)
{
    for (uint8_t i = 0; i < NBYTES_STATE; i++)
        state[i] = invsbox[state[i]];
}


/*
 * The function shift_rows shifts rows of state to the left.
 * Shifting offset is different per row where shifting offset = Row number.
 * This implementation shifts rows by swapping bytes of state according to
 * pre-defined shiftrow indexes in shiftrow_idx enum
 */

void
shift_rows(uint8_t *state)
{
    uint8_t tmp[NBYTES_STATE];
    tmp[0]  = state[B00]; tmp[1]  = state[B01];
    tmp[2]  = state[B02]; tmp[3]  = state[B03];
    tmp[4]  = state[B10]; tmp[5]  = state[B11];
    tmp[6]  = state[B12]; tmp[7]  = state[B13];
    tmp[8]  = state[B20]; tmp[9]  = state[B21];
    tmp[10] = state[B22]; tmp[11] = state[B23];
    tmp[12] = state[B30]; tmp[13] = state[B31];
    tmp[14] = state[B32]; tmp[15] = state[B33];
    memcpy(state, tmp, NBYTES_STATE * sizeof(uint8_t));
    NP_CHECK(state)
}


/*
 * The function inv_shift_rows reverses shift_rows operation.
 * The function is identical to shift_rows with only indexes being swapped.
 */

void
inv_shift_rows(uint8_t *state)
{
    uint8_t tmp[NBYTES_STATE];
    tmp[B00] = state[0] ; tmp[B01] = state[1] ;
    tmp[B02] = state[2] ; tmp[B03] = state[3] ;
    tmp[B10] = state[4] ; tmp[B11] = state[5] ;
    tmp[B12] = state[6] ; tmp[B13] = state[7] ;
    tmp[B20] = state[8] ; tmp[B21] = state[9] ;
    tmp[B22] = state[10]; tmp[B23] = state[11];
    tmp[B30] = state[12]; tmp[B31] = state[13];
    tmp[B32] = state[14]; tmp[B33] = state[15];
    memcpy(state, tmp, NBYTES_STATE * sizeof(uint8_t));
    NP_CHECK(state)
}


/*
 * The function mix_columns performs a matrix multiplication on the state.
 * Each column is treated as a four-term polynomial over GF(2^8) which is then
 * multiplied with a fixed polynomial a(x):
 *
 *      r0 = {2} • a0 + {3} • a1 + {1} • a2 + {1} • a3
 *      r1 = {1} • a0 + {2} • a1 + {3} • a2 + {1} • a3
 *      r2 = {1} • a0 + {1} • a1 + {2} • a2 + {3} • a3
 *      r3 = {3} • a0 + {1} • a1 + {1} • a2 + {2} • a3
 *
 */

void
mix_columns(uint8_t *state)
{
    uint8_t a[4];
    for (uint8_t i = 0; i < NWORDS_STATE; i++) {
        a[0] = state[i * 4 + 0];
        a[1] = state[i * 4 + 1];
        a[2] = state[i * 4 + 2];
        a[3] = state[i * 4 + 3];

        state[i * 4 + 0] = gmul(a[0], 0x02) ^ gmul(a[1], 0x03) ^ a[2] ^ a[3];
        state[i * 4 + 1] = a[0] ^ gmul(a[1], 0x02) ^ gmul(a[2], 0x03) ^ a[3];
        state[i * 4 + 2] = a[0] ^ a[1] ^ gmul(a[2], 0x02) ^ gmul(a[3], 0x03);
        state[i * 4 + 3] = gmul(a[0], 0x03) ^ a[1] ^ a[2] ^ gmul(a[3], 0x02);
    }
}


/*
 * The function inv_mix_columns performs a matrix multiplication on the state such
 * that mix_columns operation on state is reversed.
 * Each column is treated as a four-term polynomial over GF(2^8) which is then
 * multiplied with a fixed polynomial a(x):
 *
 *      r0 = {0e} • a0 + {0b} • a1 + {0d} • a2 + {09} • a3
 *      r1 = {09} • a0 + {0e} • a1 + {0b} • a2 + {0d} • a3
 *      r2 = {0d} • a0 + {09} • a1 + {0e} • a2 + {0b} • a3
 *      r3 = {0b} • a0 + {0d} • a1 + {09} • a2 + {0e} • a3
 *
 */

void
inv_mix_columns(uint8_t *state)
{
    uint8_t a[4];
    for (uint8_t i = 0; i < NWORDS_STATE; i++) {
        a[0] = state[i * 4 + 0];
        a[1] = state[i * 4 + 1];
        a[2] = state[i * 4 + 2];
        a[3] = state[i * 4 + 3];

        state[i * 4 + 0] = gmul(a[0], 0x0e) ^ gmul(a[1], 0x0b) ^ \
                           gmul(a[2], 0x0d) ^ gmul(a[3], 0x09);
        state[i * 4 + 1] = gmul(a[0], 0x09) ^ gmul(a[1], 0x0e) ^ \
                           gmul(a[2], 0x0b) ^ gmul(a[3], 0x0d);
        state[i * 4 + 2] = gmul(a[0], 0x0d) ^ gmul(a[1], 0x09) ^ \
                           gmul(a[2], 0x0e) ^ gmul(a[3], 0x0b);
        state[i * 4 + 3] = gmul(a[0], 0x0b) ^ gmul(a[1], 0x0d) ^ \
                           gmul(a[2], 0x09) ^ gmul(a[3], 0x0e);
    }
}


/*
 * The function add_round_key adds the current round key to the state buffer by a
 * XOR operation.
 * A pointer to the expanded key buffer is passed to add_round_key along with the
 * current round index r_i, allowing add_round_key to XOR the state with the correct
 * round key.
 * The inverse of the add_round_key operation is add_round_key as the inverse of
 * XOR is itself.
 */

void
add_round_key(uint8_t *state, const uint8_t *w, uint8_t r_i)
{
    for (uint8_t i = 0; i < NBYTES_STATE; i++)
        state[i] ^= w[i + 16 * r_i];
}


/*
 * The function AES_cipher_block AES ciphers an plain text 16 byte block
 * from an AES key
 */

void
AES_cipher_block(const uint8_t *in, uint8_t *out, const aes_ctx_s *ctx)
{
    uint8_t r_i = 0; // round index
    uint8_t state[NBYTES_STATE];
    memcpy(state, in, NBYTES_STATE * sizeof(uint8_t));

    // Add first round key to the state before starting rounds.
    add_round_key(state, ctx->expkey, r_i);

    // There are a total of Nr rounds per block ciphering.
    // The first Nr - 1 rounds are identical.
    for (r_i = 1; r_i < ctx->key->Nr; r_i++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, ctx->expkey, r_i);
    }

    // Last round without mix_columns operation.
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, ctx->expkey, r_i);

    memcpy(out, state, NBYTES_STATE * sizeof(uint8_t));
}


/*
 * The function AES_invcipher_block deciphers an AES encrypted 16 byte block
 * from a correct AES key.
 */

void
AES_invcipher_block(const uint8_t *in, uint8_t *out, const aes_ctx_s *ctx)
{
    // Start round index from Nr so that it can be decremented in rounds loop.
    uint8_t r_i = ctx->key->Nr;
    uint8_t state[NBYTES_STATE];
    memcpy(state, in, NBYTES_STATE * sizeof(uint8_t)); NP_CHECK(state)

    // Add  first round key to the state before starting  rounds.
    add_round_key(state, ctx->expkey, r_i);

    // There are a total of Nr rounds per block deciphering.
    // The first Nr - 1 rounds are identical.
    for (r_i-- ; r_i >= 1; r_i--) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, ctx->expkey, r_i);
        inv_mix_columns(state);
    }

    // Last round without mix_columns operation.
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, ctx->expkey, 0);

    memcpy(out, state, NBYTES_STATE * sizeof(uint8_t));
}


/*
 * The function AES_ctx_init initializes a new context for AES block ciphering.
 * AES key is initialized in aes_key_s data structure and its key is expanded into
 * large enough buffer. AES key and expanded key buffer are stored in aes_ctx_s
 * data structure.
 *
 * aes_key_s data structure is initialized according to key length:
 *
 *            | Key Length | Block Size | Number of Rounds
 *            | (Nk words) | (Nb words) | (Nr)
 *            --------------------------------------------
 *    AES-128 | 4          | 4         | 10
 *            --------------------------------------------
 *    AES-192 | 6          | 4         | 12
 *            --------------------------------------------
 *    AES-256 | 8          | 4         | 14
 */

aes_ctx_s*
AES_ctx_init(uint8_t *key, uint16_t key_bitlen)
{
    aes_ctx_s *new_ctx = malloc(sizeof(aes_ctx_s)); NP_CHECK(new_ctx)
    aes_key_s *new_key = malloc(sizeof(aes_key_s)); NP_CHECK(new_key)

    new_ctx->key = new_key;
    switch (key_bitlen) {
        case KEY128:
            new_ctx->key->b  = key;
            new_ctx->key->Nk = 4;
            new_ctx->key->Nb = 4;
            new_ctx->key->Nr = 10;
            new_ctx->expkey = malloc(NBYTES_EXPKEY128 * sizeof(uint8_t));
            NP_CHECK(new_ctx->expkey)
            expand_key(new_ctx->key, new_ctx->expkey);
            break;
        case KEY192:
            new_ctx->key->b  = key;
            new_ctx->key->Nk = 6;
            new_ctx->key->Nb = 4;
            new_ctx->key->Nr = 12;
            new_ctx->expkey = malloc(NBYTES_EXPKEY192 * sizeof(uint8_t));
            NP_CHECK(new_ctx->expkey)
            expand_key(new_ctx->key, new_ctx->expkey);
            break;
        case KEY256:
            new_ctx->key->b  = key;
            new_ctx->key->Nk = 8;
            new_ctx->key->Nb = 4;
            new_ctx->key->Nr = 14;
            new_ctx->expkey = malloc(NBYTES_EXPKEY256 * sizeof(uint8_t));
            NP_CHECK(new_ctx->expkey)
            expand_key(new_ctx->key, new_ctx->expkey);
            break;
        default:
#ifdef DEBUG
            DBGPRINT(KRED"Unsupported key length: %d bits. Terminate "
                         "encryption."KNRM, key_bitlen);
#endif
            return NULL;
    }
    return new_ctx;
}


/*
 * The function AES_ctx_destroy frees any dynamic memory allocated while initializing
 * new AES context with AES_ctx_init
 */

void
AES_ctx_destroy(aes_ctx_s *ctx)
{
    free(ctx->key);
    free(ctx->expkey);
    free(ctx);
}
