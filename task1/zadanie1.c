#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>

#define ERR(str) fprintf(stderr, "%s\n", str)
#define ERR_LIB(call_name, str) \
    do {                        \
        perror(call_name);      \
        ERR(str);               \
    } while(0)

#define OPT_STR "sdp:i:o:"

/* General rotate word functions */
#define ROTW_R(x, b) \
   (((x) >> b) | ((x) << (32 - (b))))
#define ROTW_L(x, b) \
    (((x) << b) | ((x) >> (32 - (b))))

/* SHA-256 functions (Sec. 4.1.2) */
#define SHA256_CH(x, y, z) \
    (((x) & (y)) ^ (~(x) & (z)))
#define SHA256_MAJ(x, y, z) \
    (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define SHA256_SUM_0(x) \
    (ROTW_R(x, 2) ^ ROTW_R(x, 13) ^ ROTW_R(x, 22))
#define SHA256_SUM_1(x) \
    (ROTW_R(x, 6) ^ ROTW_R(x, 11) ^ ROTW_R(x, 25))

#define SHA256_SIGMA_0(x) \
    (ROTW_R(x, 7) ^ ROTW_R(x, 18) ^ ((x) >> 3))
#define SHA256_SIGMA_1(x) \
    (ROTW_R(x, 17) ^ ROTW_R(x, 19) ^ ((x) >> 10))

struct opts {
    int enc;
    const char *pwd;
    const char *file_in;
    const char *file_out;
};

/* AES Spec: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf */
/* SHA256 Spec: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf */
/* PKCS#7 Spec: https://datatracker.ietf.org/doc/html/rfc5652#section-6.3 */

/* Byte - size 1 byte */
typedef unsigned char byte;

/* Word - size 4 bytes */
typedef unsigned int word;

enum {
    /* AES word size, in bytes */
    word_sz            = 4,

    /* AES block size, in words */
    aes_block_sz_w     = 4,

    /* AES block size, in bytes */
    aes_block_sz       = aes_block_sz_w * word_sz,

    /* AES-256 number of rounds */
    aes_round_no       = 14,

    /* AES-256 key size, in words */
    aes_key_sz_w       = 8,

    /* AES-256 key size, in bytes */
    aes_key_sz         = aes_key_sz_w * word_sz,

    /* AES-256 key schedule size, in words */
    aes_key_sched_sz_w = 4 * (aes_round_no + 1),

    /* AES-256 key schedule size, in bytes */
    aes_key_sched_sz   = aes_key_sched_sz_w * word_sz,

    /* SHA-256 hash size, in words */
    sha256_hash_sz_w   = 8,

    /* SHA-256 block size, in bytes */
    sha256_block_sz    = 64,

    /* SHA-256 message schedule size, in words */
    sha256_msg_sched_sz_w = 64
};

/* AES round constants. Used for AES KeyExpansion (Sec. 5.2) */
static const word aes_rcon[11] = {
    0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
    0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000
};

/* Pre-computed AES SBox values for a single byte (Sec. 5.1.1) */
static const byte aes_sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16
};

/* Pre-computed AES inverted SBox values for a single byte (Sec. 5.3.2) */
static const byte aes_sbox_inv[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
    0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
    0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
    0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
    0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
    0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
    0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
    0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
    0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
    0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
    0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0c, 0x7d
};

/* SHA-256 Initial Hash Values (Sec. 5.3.3) */
static const word sha256_hash_init[sha256_hash_sz_w] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
    0x1f83d9ab, 0x5be0cd19
};

/* SHA-256 round constants (Sec. 4.2.2) */
static const word sha256_rcon[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* AES xTimes implementation (Sec. 4.2) */
static byte aes_x_times(byte b)
{
    if(b & 0x80) {
        return (b << 1) ^ 0x1B;
    } else {
        return b << 1;
    }
}

/* AES multiply two bytes in GF(2^8) (Sec. 4.2) */
static byte aes_mul_bytes(byte b1, byte b2)
{
    int i;
    byte res = 0;
    byte mul_res = b1;

    for(i = 0; i < 8; i++) {
        if(i) {
            mul_res = aes_x_times(mul_res);
        }

        if(b2 & (0x1 << i)) {
            res ^= mul_res;
        }
    }

    return res;
}

/* AES SubWord implementation (Sec. 5.2) */
static void aes_sub_word(word *word)
{
    *word =
        (aes_sbox[((*word) >> 0 ) & 0xFF] << 0 ) |
        (aes_sbox[((*word) >> 8 ) & 0xFF] << 8 ) |
        (aes_sbox[((*word) >> 16) & 0xFF] << 16) |
        (aes_sbox[((*word) >> 24) & 0xFF] << 24);
}

/* AES InvMixColumns implementation (Sec. 5.3.3) */
static void aes_inv_mix_columns(byte *state)
{
    byte state_temp[aes_block_sz];
    unsigned int i;

    for(i = 0; i < sizeof(state_temp); i += 4) {
        state_temp[i + 0] = aes_mul_bytes(0xE, state[i + 0]) ^
                            aes_mul_bytes(0xB, state[i + 1]) ^
                            aes_mul_bytes(0xD, state[i + 2]) ^
                            aes_mul_bytes(0x9, state[i + 3]);

        state_temp[i + 1] = aes_mul_bytes(0x9, state[i + 0]) ^
                            aes_mul_bytes(0xE, state[i + 1]) ^
                            aes_mul_bytes(0xB, state[i + 2]) ^
                            aes_mul_bytes(0xD, state[i + 3]);

        state_temp[i + 2] = aes_mul_bytes(0xD, state[i + 0]) ^
                            aes_mul_bytes(0x9, state[i + 1]) ^
                            aes_mul_bytes(0xE, state[i + 2]) ^
                            aes_mul_bytes(0xB, state[i + 3]);

        state_temp[i + 3] = aes_mul_bytes(0xB, state[i + 0]) ^
                            aes_mul_bytes(0xD, state[i + 1]) ^
                            aes_mul_bytes(0x9, state[i + 2]) ^
                            aes_mul_bytes(0xE, state[i + 3]);
    }

    memcpy(state, state_temp, sizeof(state_temp));
}

/* AES MixColumns implementation (Sec. 5.1.3) */
static void aes_mix_columns(byte *state)
{
    byte state_temp[aes_block_sz];
    unsigned int i;

    for(i = 0; i < sizeof(state_temp); i += 4) {
        state_temp[i + 0] = aes_mul_bytes(0x2, state[i + 0]) ^
                            aes_mul_bytes(0x3, state[i + 1]) ^
                            state[i + 2] ^
                            state[i + 3];

        state_temp[i + 1] = state[i + 0] ^
                            aes_mul_bytes(0x2, state[i + 1]) ^
                            aes_mul_bytes(0x3, state[i + 2]) ^
                            state[i + 3];

        state_temp[i + 2] = state[i + 0] ^
                            state[i + 1] ^
                            aes_mul_bytes(0x2, state[i + 2]) ^
                            aes_mul_bytes(0x3, state[i + 3]);

        state_temp[i + 3] = aes_mul_bytes(0x3, state[i + 0]) ^
                            state[i + 1] ^
                            state[i + 2] ^
                            aes_mul_bytes(0x2, state[i + 3]);
    }

    memcpy(state, state_temp, sizeof(state_temp));
}

/* AES ShiftRows/InvShiftRows implementation (Sec. 5.1.2, 5.3.1) */
static void aes_shift_rows(byte *state, int inv)
{
    byte state_temp[aes_block_sz];
    unsigned int i;
    int row;
    int col;
    int col_n;

    for(i = 0; i < sizeof(state_temp); i++) {
        row = i % 4;
        col = i / 4;
        if(inv) {
            col_n = col - row;
            if(col_n < 0) {
                col_n = col_n + 4;
            }
        } else {
            col_n = (col + row) % 4;
        }
        state_temp[i] = state[col_n * 4 + row];
    }

    memcpy(state, state_temp, sizeof(state_temp));
}

/* AES SubBytes/InvSubBytes implementation (Sec. 5.1.1, 5.3.2) */
static void aes_sub_bytes(byte *state, int inv)
{
    int i;

    for(i = 0; i < aes_block_sz; i++) {
        state[i] = inv ? aes_sbox_inv[state[i]] : aes_sbox[state[i]];
    }
}

/* AES AddRoundKey implementation (Sec. 5.1.4) */
static void aes_add_round_key(byte *state, const word *round_key)
{
    int i;
    int col;

    for(i = 0; i < aes_block_sz_w; i++) {
        col = i * 4;
        state[col + 0] ^= ((round_key[i] >> 24) & 0xFF);
        state[col + 1] ^= ((round_key[i] >> 16) & 0xFF);
        state[col + 2] ^= ((round_key[i] >> 8 ) & 0xFF);
        state[col + 3] ^= ((round_key[i] >> 0 ) & 0xFF);
    }
}

/* AES InvCipher implementation (Sec. 5.3) */
static void aes_inv_cipher(byte *block, const word *key_sched)
{
    int r;

    aes_add_round_key(block, key_sched + 4 * aes_round_no);

    for(r = aes_round_no - 1; r >= 1; r--) {
        aes_shift_rows(block, 1);
        aes_sub_bytes(block, 1);
        aes_add_round_key(block, key_sched + 4 * r);
        aes_inv_mix_columns(block);
    }

    aes_shift_rows(block, 1);
    aes_sub_bytes(block, 1);
    aes_add_round_key(block, key_sched);
}

/* AES Cipher implementation (Sec. 5.1) */
static void aes_cipher(byte *block, const word *key_sched)
{
    int r;

    aes_add_round_key(block, key_sched);

    for(r = 1; r < aes_round_no; r++) {
        aes_sub_bytes(block, 0);
        aes_shift_rows(block, 0);
        aes_mix_columns(block);
        aes_add_round_key(block, key_sched + 4 * r);
    }

    aes_sub_bytes(block, 0);
    aes_shift_rows(block, 0);
    aes_add_round_key(block, key_sched + 4 * aes_round_no);
}

/* AES KeyExpansion implementation (Sec. 5.2) */
static void aes_key_expansion(const byte *key, word *key_sched)
{
    int i;
    word temp;

    /* Copy first Nk words of the key to the expanded key */
    memcpy(key_sched, key, aes_key_sz);

    /* Generate subsequent words */
    for(i = aes_key_sz_w; i < aes_key_sched_sz_w; i++) {
        temp = key_sched[i - 1];

        if(i % aes_key_sz_w == 0) {
            temp = ROTW_L(temp, 8);
            aes_sub_word(&temp);
            temp ^= aes_rcon[i / aes_key_sz_w];
        } else if(i % aes_key_sz_w == 4) {
            aes_sub_word(&temp);
        }

        key_sched[i] = key_sched[i - aes_key_sz_w] ^ temp;
    }
}

/* Compute SHA-256 hash from preprocessed message (Sec. 6.2.2) */
static void sha256_compute(const word *msg, int msg_sz_blk, word *hash)
{
    int i, j;
    word a, b, c, d, e, f, g, h, t1, t2;
    word msg_sched[sha256_msg_sched_sz_w];

    /* Initialize hash values */
    memcpy(hash, sha256_hash_init, sizeof(sha256_hash_init));

    for(i = 0; i < msg_sz_blk; i++) {
        memcpy(msg_sched, msg + i * sha256_block_sz / word_sz, 16 * word_sz);

        for(j = 16; j < sha256_msg_sched_sz_w; j++) {
            msg_sched[j] =
                SHA256_SIGMA_1(msg_sched[j - 2]) + msg_sched[j - 7] +
                SHA256_SIGMA_0(msg_sched[j - 15]) + msg_sched[j - 16];
        }

        a = hash[0];
        b = hash[1];
        c = hash[2];
        d = hash[3];
        e = hash[4];
        f = hash[5];
        g = hash[6];
        h = hash[7];

        for(j = 0; j < sha256_msg_sched_sz_w; j++) {
            t1 = h + SHA256_SUM_1(e) + SHA256_CH(e, f, g) + sha256_rcon[j] +
                msg_sched[j];
            t2 = SHA256_SUM_0(a) + SHA256_MAJ(a, b, c);

            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        hash[0] += a;
        hash[1] += b;
        hash[2] += c;
        hash[3] += d;
        hash[4] += e;
        hash[5] += f;
        hash[6] += g;
        hash[7] += h;
    }
}

/* Allocate memory and preprocess message for SHA-256 hash computation */
static word *sha256_alloc_prep_msg(const char *msg, int *msg_sz_blk)
{
    int msg_len;
    int msg_len_bits;
    word *msg_pad;
    int msg_pad_sz;

    /* Msg must not be longer than 4GiB (size written in 4 bytes int) */
    msg_len = strlen(msg);
    msg_len_bits = msg_len * 8;

    /* Determine length of padded message, in 512-bit blocks (Sec. 5.1.1) */
    *msg_sz_blk = (msg_len_bits + 1 + 64) / (sha256_block_sz * 8) + 1;
    msg_pad_sz = *msg_sz_blk * sha256_block_sz;

    msg_pad = calloc(msg_pad_sz, 1);

    /* Fill padded bytes (Sec. 5.1.1) */

    memcpy(msg_pad, msg, msg_len);

    /* Set bit after msg in endian-independent way */
    msg_pad[msg_len / word_sz] = 0x80 << ((3 - (msg_len % word_sz)) * 8);

    msg_pad[msg_pad_sz / word_sz - 1] = msg_len_bits;

    return msg_pad;
}

/* PKCS#7 get existing padding implementation */
static unsigned int pkcs7_get_pad(byte *buf)
{
    return buf[aes_block_sz - 1];
}

/* PKCS#7 padding add implementation */
static void pkcs7_pad(byte *buf, unsigned int sz_read)
{
    byte padding;

    /* Determine padding */
    padding = aes_block_sz - (sz_read % aes_block_sz);

    /* Fill padded space with padding value */
    memset(buf + sz_read, padding, aes_block_sz - sz_read);
}

static int fd_is_eof(int fd)
{
    long long pos;
    int res;

    /* Backup stream position */
    pos = lseek(fd, 0, SEEK_CUR);
    if(pos == -1) {
        ERR_LIB("lseek()", "Failed to obtain current stream position");
        return -1;
    }

    /* Try to read a single byte */
    res = read(fd, &res, 1);
    if(res == -1) {
        ERR_LIB("read()", "Failed to read test byte");
        return -1;
    }

    /* Return stream position */
    pos = lseek(fd, pos, SEEK_SET);
    if(pos == -1) {
        ERR_LIB("lseek()", "Failed to set stream position");
        return -1;
    }

    return !res;
}

static int
data_process(const struct opts *opts, const word *aes_key_sched)
{
    int fd_in;
    int fd_out;
    int res;
    byte buf[aes_block_sz];
    int close_res;
    int is_eof;
    int sz;
    unsigned int sz_read;
    unsigned int sz_to_write;
    unsigned int sz_write;

    /* Open input/output files */
    fd_in = open(opts->file_in, O_RDONLY);
    if(fd_in == -1) {
        ERR_LIB("open()", "Failed to open input file");
        return 1;
    }

    fd_out = open(opts->file_out, O_WRONLY|O_CREAT|O_TRUNC, 0666);
    if(fd_out == -1) {
        ERR_LIB("open()", "Failed to open output file");
        return 1;
    }

    /* Read AES block -> process AES block -> write AES block loop */
    do {
        sz_read = 0;
        sz_to_write = 0;
        sz_write = 0;

        /* Read block or until no more data to read */
        while(sz_read < sizeof(buf)) {
            sz = read(fd_in, buf + sz_read, sizeof(buf) - sz_read);
            if(sz == -1) {
                ERR_LIB("read()", "Failed to read input file");
                res = 1;
                goto exit;
            }

            /* Exit read loop if no more data to read */
            if(!sz) {
                break;
            }

            sz_read += sz;
        }

        if(opts->enc) {
            /* Last iteration flag */
            is_eof = sz_read < sizeof(buf);

            if(is_eof) {
                /* Pad the rest of the space */
                pkcs7_pad(buf, sz_read);
            }

            aes_cipher(buf, aes_key_sched);

            /* Write whole block */
            sz_to_write = sizeof(buf);
        } else {
            /* Last iteration flag */
            is_eof = fd_is_eof(fd_in);
            if(is_eof == -1) {
                res = 1;
                goto exit;
            }

            /* File is not aliged with AES block size */
            if(sz_read < sizeof(buf)) {
                ERR("Input file is not aligned with AES block size");
                res = 1;
                goto exit;
            }

            aes_inv_cipher(buf, aes_key_sched);

            if(is_eof) {
                /* Unpad data */
                sz_to_write = sizeof(buf) - pkcs7_get_pad(buf);
            } else {
                /* Write whole block */
                sz_to_write = sizeof(buf);
            }
        }

        /* Write block / unpadded data */
        while(sz_write < sz_to_write) {
            sz = write(fd_out, buf + sz_write, sz_to_write - sz_write);
            if(sz < 0) {
                ERR_LIB("write()", "Failed to write output file");
                res = 1;
                goto exit;
            }

            sz_write += sz;
        }
    } while(!is_eof);

    /* Executed successfully */
    res = 0;
exit:
    /* Close input/output files */
    close_res = close(fd_in);
    if(close_res == -1) {
        ERR_LIB("close()", "Failed to close input file");
        return 1;
    }

    close_res = close(fd_out);
    if(close_res == -1) {
        ERR_LIB("close()", "Failed to close output file");
        return 1;
    }

    return res;
}

static int opts_parse(struct opts *opts, int argc, const char *const *argv)
{
    extern int optind;
    extern char *optarg;
    int c;

    if(argc <= 0) {
        ERR("No arguments passed");
        return 1;
    }

    memset(opts, 0, sizeof(*opts));
    opts->enc = -1;

    do {
        c = getopt(argc, (char **) argv, OPT_STR);

        switch(c) {
            case -1:
                break;
            case 's':
                opts->enc = 1;
                break;
            case 'd':
                opts->enc = 0;
                break;
            case 'p':
                opts->pwd = optarg;
                break;
            case 'i':
                opts->file_in = optarg;
                break;
            case 'o':
                opts->file_out = optarg;
                break;
            case ':':
                ERR("Missing argument");
                return 1;
            case '?':
                ERR("Unknown option");
                return 1;
            default:
                ERR("Unknown error");
                return 1;
        }
    } while(c != -1);

    if(opts->enc < 0) {
        ERR("Either -s or -d option must be specified");
        return 1;
    }

    if(!opts->pwd) {
        ERR("-p option must be specified");
        return 1;
    }

    if(!opts->pwd) {
        ERR("-p option must be specified");
        return 1;
    }

    if(!opts->file_in) {
        ERR("-i option must be specified");
        return 1;
    }

    if(!opts->file_out) {
        ERR("-o option must be specified");
        return 1;
    }

    return 0;
}

int main(int argc, const char *const *argv)
{
    struct opts opts;
    int res;
    word *sha256_msg;
    int sha256_msg_sz_blk;
    word sha256_key_hash[sha256_hash_sz_w];
    word aes_key_sched[aes_key_sched_sz_w];

    /* Parse input arguments */
    res = opts_parse(&opts, argc, argv);
    if(res != 0) {
        ERR("Invalid input arguments");
        return 1;
    }

    /* Preprocess SHA-256 message from password */
    sha256_msg = sha256_alloc_prep_msg(opts.pwd, &sha256_msg_sz_blk);

    /* Compute SHA-256 hash from SHA-256 message */
    sha256_compute(sha256_msg, sha256_msg_sz_blk, sha256_key_hash);

    /* Compute AES key schedule from SHA-256 hash */
    aes_key_expansion((byte *) sha256_key_hash, aes_key_sched);

    /* Perform AES encryption/decryption */
    res = data_process(&opts, aes_key_sched);
    if(res != 0) {
        ERR("Failed to process data");
        res = 1;
        goto exit;
    }

    res = 0;
exit:
    free(sha256_msg);
    return res;
}

