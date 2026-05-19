#ifndef PARALLEL_AES_AES_H
#define PARALLEL_AES_AES_H

/* Byte - size 1 byte */
typedef unsigned char aes_byte;

/* Word - size 4 bytes */
typedef unsigned int aes_word;

enum {
    /* AES-256 number of rounds */
    aes_round_no       = 14,

    /* AES-256 word size, in bytes */
    aes_word_sz        = 4,

    /* AES-256 block size, in words */
    aes_block_sz_w     = 4,

    /* AES-256 block size, in bytes */
    aes_block_sz       = aes_block_sz_w * aes_word_sz,

    /* AES-256 key size, in words */
    aes_key_sz_w       = 8,

    /* AES-256 key size, in bytes */
    aes_key_sz         = aes_key_sz_w * aes_word_sz,

    /* AES-256 key schedule size, in words */
    aes_key_sched_sz_w = 4 * (aes_round_no + 1),

    /* AES-256 key schedule size, in bytes */
    aes_key_sched_sz   = aes_key_sched_sz_w * aes_word_sz
};

/* AES KeyExpansion implementation (Sec. 5.2) */
void aes_key_expansion(const aes_byte *key, aes_word *key_sched);

/* AES Cipher implementation (Sec. 5.1) */
void aes_cipher(aes_byte *block, const aes_word *key_sched);

/* AES InvCipher implementation (Sec. 5.3) */
void aes_inv_cipher(aes_byte *block, const aes_word *key_sched);

#endif

