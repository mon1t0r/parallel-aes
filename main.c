#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>

#include "err.h"
#include "aes.h"
#include "sha256.h"
#include "pkcs7.h"

#define OPT_STR "sdp:i:o:"

struct opts {
    int enc;
    const char *pwd;
    const char *file_in;
    const char *file_out;
};

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
data_process(const struct opts *opts, const aes_word *aes_key_sched)
{
    int fd_in;
    int fd_out;
    int res;
    aes_byte buf[aes_block_sz];
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
                pkcs7_pad(buf, sz_read, aes_block_sz);
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
                sz_to_write = sizeof(buf) - pkcs7_get_pad(buf, aes_block_sz);
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
    sha256_word *sha256_msg;
    int sha256_msg_sz_blk;
    sha256_word sha256_key_hash[sha256_hash_sz_w];
    aes_word aes_key_sched[aes_key_sched_sz_w];

    /* Reality check */
    if(sha256_hash_sz != (int) aes_key_sz) {
        ERR("SHA hash size does not match AES key size");
        return 1;
    }

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
    aes_key_expansion((aes_byte *) sha256_key_hash, aes_key_sched);

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

