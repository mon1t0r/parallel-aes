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

struct opts {
    int enc;
    const char *pwd;
    const char *file_in;
    const char *file_out;
};

/* AES Spec: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf */

/* AES word - size 4 bytes */
typedef unsigned int aes_word;

/* AES byte - size 1 byte */
typedef unsigned char aes_byte;

enum {
    /* AES word size, in bytes */
    aes_word_sz    = 4,

    /* AES block size, in words */
    aes_block_sz_w = 4,

    /* AES block size, in bytes */
    aes_block_sz   = aes_block_sz_w * aes_word_sz,

    /* AES-256 number of rounds */
    aes_round_no   = 14,

    /* AES-256 key size, in words */
    aes_key_sz_w   = 8,

    /* AES-256 key size, in bytes */
    aes_key_sz     = aes_key_sz_w * aes_word_sz,

    /* AES-256 key schedule size, in words */
    aes_key_sched_sz_w = 4 * (aes_round_no + 1),

    /* AES-256 key schedule size, in bytes */
    aes_key_sched_sz   = aes_key_sched_sz_w * aes_word_sz
};

/* AES round constants. Used for AES KeyExpansion (Sec. 5.2) */
static const aes_word rcon[10] = {
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000,
    0x40000000, 0x80000000, 0x1b000000, 0x36000000
};

/* Pre-computed AES SBox values for a single byte (Sec. 5.1.1)*/
static const aes_byte sbox[256] = {
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

/* AES xTimes implementation (Sec. 4.2) */
static aes_byte aes_x_times(aes_byte b)
{
    if(b & 0x80) {
        return (b << 1) & 0x1B;
    } else {
        return b << 1;
    }
}

/* AES multiply two bytes in GF(2^8) (Sec. 4.2) */
static aes_byte aes_mul_bytes(aes_byte b1, aes_byte b2)
{
    int i;
    aes_byte res = 0;
    aes_byte mul_res = b1;

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

/* AES RotWord implementation (sec. 5.2) */
static void aes_rot_word(aes_word *word)
{
    *word = ((*word) << 8) | (((*word) & 0xFF000000) >> 24);
}

/* AES SubWord implementation (sec. 5.2) */
static void aes_sub_word(aes_word *word)
{
    *word =
        (sbox[((*word) >> 0 ) & 0xFF] << 0 ) |
        (sbox[((*word) >> 8 ) & 0xFF] << 8 ) |
        (sbox[((*word) >> 16) & 0xFF] << 16) |
        (sbox[((*word) >> 24) & 0xFF] << 24);
}

/* AES MixColumns implementation (sec. 5.1.3) */
static void aes_mix_columns(aes_byte *state)
{
    aes_byte state_temp[aes_block_sz];
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

/* AES ShiftRows implementation (sec. 5.1.2) */
static void aes_shift_rows(aes_byte *state)
{
    aes_byte state_temp[aes_block_sz];
    unsigned int i;
    int row;
    int col;
    int col_n;

    for(i = 0; i < sizeof(state_temp); i++) {
        row = i % 4;
        col = i / 4;
        col_n = (col + row) % 4;
        state_temp[i] = state[col_n * 4 + row];
    }

    memcpy(state, state_temp, sizeof(state_temp));
}

/* AES SubBytes implementation (sec. 5.1.1) */
static void aes_sub_bytes(aes_byte *state)
{
    int i;

    for(i = 0; i < aes_block_sz; i++) {
        state[i] = sbox[state[i]];
    }
}

/* AES AddRoundKey implementation (sec. 5.1.4) */
static void aes_add_round_key(aes_byte *state, const aes_word *round_key)
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

#if 0
/* AES InvCipher implementation (sec. 5.3) */
static void
aes_inv_cipher(aes_byte *block, const aes_word *key_sched)
{
    
}
#endif

/* AES Cipher implementation (sec. 5.1) */
static void aes_cipher(aes_byte *block, const aes_word *key_sched)
{
    int r;

    aes_add_round_key(block, key_sched);

    for(r = 1; r < aes_round_no; r++) {
        aes_sub_bytes(block);
        aes_shift_rows(block);
        aes_mix_columns(block);
        aes_add_round_key(block, key_sched + 4 * r);
    }

    aes_sub_bytes(block);
    aes_shift_rows(block);
    aes_add_round_key(block, key_sched + 4 * aes_round_no);
}

/* AES KeyExpansion implementation (sec. 5.2) */
static void aes_key_expansion(const aes_byte *key, aes_word *key_sched)
{
    int i;
    aes_word temp;

    /* Copy first Nk words of the key to the expanded key */
    memcpy(key_sched, key, aes_key_sz);

    /* Generate subsequent words  */
    for(i = aes_key_sz_w; i < aes_key_sched_sz_w; i++) {
        temp = key_sched[i - 1];

        if(i % aes_key_sz_w == 0) {
            aes_rot_word(&temp);
            aes_sub_word(&temp);
            temp ^= rcon[i / aes_key_sz_w];
        } else if(i % aes_key_sz_w == 4) {
            aes_sub_word(&temp);
        }

        key_sched[i] = key_sched[i - aes_key_sz_w] ^ temp;
    }
}

static int
data_process(const struct opts *opts, const aes_word *aes_key_sched)
{
    int fd_in;
    int fd_out;
    int res;
    aes_byte buf[aes_block_sz];
    int close_res;
    int sz;
    unsigned int sz_read;
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
        sz_write = 0;

        /* Read block or until no more data to read */
        while(sz_read < sizeof(buf)) {
            sz = read(fd_in, buf + sz_read, sizeof(buf) - sz_read);
            if(sz == -1) {
                ERR_LIB("read()", "Failed to read input file");
                res = 1;
                goto exit;
            }

            /* Exit loop if no more data to read */
            if(!sz) {
                break;
            }

            sz_read += sz;
        }

        /* If no data was read, exit loop */
        if(!sz_read) {
            break;
        }

        /* If read less than buf size, fill the rest of block with zeroes */
        if(sz_read < sizeof(buf)) {
            memset(buf + sz_read, 0, sizeof(buf) - sz_read);
        }

        if(opts->enc) {
            aes_cipher(buf, aes_key_sched);
        } else {
            aes_inv_cipher(buf, aes_key_sched);
        }

        /* Write block */
        while(sz_write < sizeof(buf)) {
            sz = write(fd_out, buf + sz_write, sizeof(buf) - sz_write);
            if(sz < 0) {
                ERR_LIB("write()", "Failed to write output file");
                res = 1;
                goto exit;
            }

            sz_write += sz;
        }
    } while(sz_read >= sizeof(buf));

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
    aes_word aes_key_sched[aes_key_sched_sz_w];

    /* Parse input arguments */
    res = opts_parse(&opts, argc, argv);
    if(res != 0) {
        ERR("Invalid input arguments");
        return 1;
    }

    /* TODO: Complement pwd to be 256 bit (16 byte) width */
    /* Compute AES key schedule from password */
    aes_key_expansion((aes_byte *)opts.pwd, aes_key_sched);

    /* Perform AES encryption/decryption */
    res = data_process(&opts, aes_key_sched);
    if(res != 0) {
        ERR("Failed to process data");
        return 1;
    }

    return 0;
}

