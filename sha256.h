#ifndef PARALLEL_AES_SHA256_H
#define PARALLEL_AES_SHA256_H

/* Word - size 4 bytes */
typedef unsigned int sha256_word;

enum {
    /* SHA-256 word size, in bytes */
    sha256_word_sz            = 4,

    /* SHA-256 hash size, in words */
    sha256_hash_sz_w   = 8,

    /* SHA-256 hash size, in bytes */
    sha256_hash_sz     = sha256_hash_sz_w * sha256_word_sz,

    /* SHA-256 block size, in bytes */
    sha256_block_sz    = 64,

    /* SHA-256 message schedule size, in words */
    sha256_msg_sched_sz_w = 64
};

/* Allocate memory and preprocess message for SHA-256 hash computation */
sha256_word *sha256_alloc_prep_msg(const char *msg, int *msg_sz_blk);

/* Compute SHA-256 hash from preprocessed message (Sec. 6.2.2) */
void sha256_compute(const sha256_word *msg, int msg_sz_blk, sha256_word *hash);

#endif

