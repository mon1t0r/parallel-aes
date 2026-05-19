#include <stdlib.h>
#include <string.h>
#include "rot.h"

#include "sha256.h"

/* SHA-256 Spec: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf */

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

/* SHA-256 Initial Hash Values (Sec. 5.3.3) */
static const sha256_word sha256_hash_init[sha256_hash_sz_w] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
    0x1f83d9ab, 0x5be0cd19
};

/* SHA-256 round constants (Sec. 4.2.2) */
static const sha256_word sha256_rcon[64] = {
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

sha256_word *sha256_alloc_prep_msg(const char *msg, int *msg_sz_blk)
{
    int msg_len;
    int msg_len_bits;
    sha256_word *msg_pad;
    int msg_pad_sz;
    int i;

    /* Msg must not be longer than 4GiB (size written in 4 bytes int) */
    msg_len = strlen(msg);
    msg_len_bits = msg_len * 8;

    /* Determine length of padded message, in 512-bit blocks (Sec. 5.1.1) */
    *msg_sz_blk = (msg_len_bits + 1 + 64) / (sha256_block_sz * 8) + 1;
    msg_pad_sz = *msg_sz_blk * sha256_block_sz;

    msg_pad = calloc(msg_pad_sz, 1);

    /* Fill padded bytes (Sec. 5.1.1) */

    memcpy(msg_pad, msg, msg_len);

    /* Set bit after msg */
    msg_pad[msg_len / sha256_word_sz] |=
        0x80 << ((msg_len % sha256_word_sz) * 8);

    /* Convert Little Endian message to SHA-256 Big Endian */
    for(i = 0; i < msg_pad_sz / sha256_word_sz; i++) {
        msg_pad[i] = (((msg_pad[i] >> 24) & 0xFF) << 0 ) |
                     (((msg_pad[i] >> 16) & 0xFF) << 8 ) |
                     (((msg_pad[i] >> 8 ) & 0xFF) << 16) |
                     (((msg_pad[i] >> 0 ) & 0xFF) << 24);
    }

    msg_pad[msg_pad_sz / sha256_word_sz - 1] = msg_len_bits;

    return msg_pad;
}

void sha256_compute(const sha256_word *msg, int msg_sz_blk, sha256_word *hash)
{
    int i, j;
    sha256_word a, b, c, d, e, f, g, h, t1, t2;
    sha256_word msg_sched[sha256_msg_sched_sz_w];

    /* Initialize hash values */
    memcpy(hash, sha256_hash_init, sizeof(sha256_hash_init));

    for(i = 0; i < msg_sz_blk; i++) {
        memcpy(msg_sched, msg + i * sha256_block_sz / sha256_word_sz,
               16 * sha256_word_sz);

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

