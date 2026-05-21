#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>

#include "err.h"
#include "aes.h"
#include "sha256.h"
#include "pkcs7.h"

#define OPT_STR "edp:i:o:"

enum {
    thread_cnt    = 5,
    thread_buf_sz = aes_block_sz * 10,
    buf_sz        = thread_buf_sz * thread_cnt
};

struct opts {
    int enc;
    const char *pwd;
    const char *file_in;
    const char *file_out;
};

struct thread_ctx {
    aes_byte *buf;
    const aes_word *aes_key_sched;
    sem_t start_sem;
    sem_t end_sem;
    bool enc;

    int block_cnt;
};

static int fd_is_eof(int fd)
{
    // Backup stream position
    long long pos = lseek(fd, 0, SEEK_CUR);
    if(pos == -1) {
        ERR_LIB("lseek()", "Failed to obtain current stream position");
        return -1;
    }

    // Try to read a single byte
    int res = read(fd, &res, 1);
    if(res == -1) {
        ERR_LIB("read()", "Failed to read test byte");
        return -1;
    }

    // Return stream position
    pos = lseek(fd, pos, SEEK_SET);
    if(pos == -1) {
        ERR_LIB("lseek()", "Failed to set stream position");
        return -1;
    }

    return !res;
}

static void *thread_main(void *data)
{
    struct thread_ctx *ctx = static_cast<struct thread_ctx*>(data);

    // Wait for main thread to allow start processing
    sem_wait(&ctx->start_sem);

    for(int i = 0; i < ctx->block_cnt; i++) {
        aes_byte *block = ctx->buf + i * aes_block_sz;
        if(ctx->enc) {
            aes_cipher(block, ctx->aes_key_sched);
        } else {
            aes_inv_cipher(block, ctx->aes_key_sched);
        }
    }

    // Notify main thread that processing finished
    sem_post(&ctx->end_sem);

    return 0;
}

static int opts_parse(struct opts *opts, int argc, const char *const *argv)
{
    extern char *optarg;

    if(argc <= 0) {
        ERR("No arguments passed");
        return 1;
    }

    memset(opts, 0, sizeof(*opts));
    opts->enc = -1;

    int c;
    do {
        c = getopt(argc, const_cast<char**>(argv), OPT_STR);

        switch(c) {
            case -1:
                break;
            case 'e':
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
        ERR("Either -e or -d option must be specified");
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
    int res;
    struct opts opts;

    // Reality check
    if(sha256_hash_sz != (int) aes_key_sz) {
        ERR("SHA hash size does not match AES key size");
        return 1;
    }

    // Parse input arguments
    res = opts_parse(&opts, argc, argv);
    if(res != 0) {
        ERR("Invalid input arguments");
        return 1;
    }


    // Allocate SHA-256 hash buffer
    sha256_word *sha256_key_hash = new sha256_word[sha256_hash_sz_w];

    // Allocate AES key schedule buffer
    aes_word *aes_key_sched = new aes_word[aes_key_sched_sz_w];

    // Preprocess SHA-256 message from password
    int sha256_msg_sz_blk;
    sha256_word *sha256_msg = sha256_alloc_prep_msg(opts.pwd, &sha256_msg_sz_blk);

    // Compute SHA-256 hash from SHA-256 message */
    sha256_compute(sha256_msg, sha256_msg_sz_blk, sha256_key_hash);

    // Free SHA-256 message
    free(sha256_msg);

    // Compute AES key schedule from SHA-256 hash
    aes_key_expansion((aes_byte *) sha256_key_hash, aes_key_sched);


    // Allocate one buffer for all threads
    aes_byte *buf = new aes_byte[buf_sz];

    // Allocate thread contexts
    struct thread_ctx *ctxs = new struct thread_ctx[thread_cnt];

    // Allocate contexts and start threads
    for(int i = 0; i < thread_cnt; i++) {
        // Fill in thread context
        ctxs[i].buf = buf + i * thread_buf_sz;
        ctxs[i].aes_key_sched = aes_key_sched;
        sem_init(&ctxs[i].start_sem, 0, 0);
        sem_init(&ctxs[i].end_sem, 0, 0);
        ctxs[i].enc = opts.enc;
        ctxs[i].block_cnt = 0;

        // Start the thread
        pthread_t thread;
        pthread_create(&thread, NULL, &thread_main, &ctxs[i]);
    }


    // Open input/output files
    int fd_in = 0, fd_out = 0;
    fd_in = open(opts.file_in, O_RDONLY);
    if(fd_in == -1) {
        ERR_LIB("open()", "Failed to open input file");
        res = 1;
        goto exit;
    }

    fd_out = open(opts.file_out, O_WRONLY|O_CREAT|O_TRUNC, 0666);
    if(fd_out == -1) {
        ERR_LIB("open()", "Failed to open output file");
        res = 1;
        goto exit;
    }

    int is_eof;
    do {
        int read_sz = 0;

        // Read buffer size or until no more data to read
        while(read_sz < buf_sz) {
            int sz = read(fd_in, buf + read_sz, buf_sz - read_sz);
            if(sz == -1) {
                ERR_LIB("read()", "Failed to read input file");
                res = 1;
                goto exit;
            }

            // No more data to read
            if(!sz) {
                break;
            }

            read_sz += sz;
        }

        if(opts.enc) {
            // Set last iteration flag
            is_eof = read_sz < buf_sz;

            if(is_eof) {
                int last_block_off = (read_sz / aes_block_sz) * aes_block_sz;

                // Pad the rest of the space of the last block
                pkcs7_pad(buf + last_block_off, read_sz - last_block_off,
                          aes_block_sz);

                read_sz = last_block_off + aes_block_sz;
            }
        } else {
            // Last iteration flag
            is_eof = fd_is_eof(fd_in);
            if(is_eof == -1) {
                res = 1;
                goto exit;
            }

            // File is not aliged with AES block size
            if(read_sz % aes_block_sz != 0) {
                ERR("Input file is not aligned with AES block size");
                res = 1;
                goto exit;
            }
        }

        // Allow threads to process buffer
        // read_sz should be aligned with aes_block_sz at this point
        int used_thread_cnt = read_sz / thread_buf_sz +
            (read_sz % thread_buf_sz ? 1 : 0);
        for(int i = 0; i < used_thread_cnt; i++) {
            int left_sz = read_sz - i * thread_buf_sz;
            int handle_sz = left_sz >= thread_buf_sz ? thread_buf_sz : left_sz;
            ctxs[i].block_cnt = handle_sz / aes_block_sz;
            sem_post(&ctxs[i].start_sem);
        }

        // Wait for every used thread to finish
        for(int i = 0; i < used_thread_cnt; i++) {
            sem_wait(&ctxs[i].end_sem);
        }

        int to_write_sz = 0;
        if(opts.enc) {
            // This should be aligned to block size
            to_write_sz = read_sz;
        } else {
            if(is_eof) {
                // Unpad data
                to_write_sz = read_sz - pkcs7_get_pad(buf, aes_block_sz);
            } else {
                // Write whole read size
                to_write_sz = read_sz;
            }
        }

        // Write buffer
        int write_sz = 0;
        while(write_sz < to_write_sz) {
            int sz = write(fd_out, buf + write_sz, to_write_sz - write_sz);
            if(sz < 0) {
                ERR_LIB("write()", "Failed to write output file");
                res = 1;
                goto exit;
            }

            write_sz += sz;
        }
    } while(!is_eof);


    // Executed successfully
    res = 0;
exit:
    // Free resources
    if(fd_in) {
        int close_res = close(fd_in);
        if(close_res == -1) {
            ERR_LIB("close()", "Failed to close input file");
            return 1;
        }
    }

    if(fd_out) {
        int close_res = close(fd_out);
        if(close_res == -1) {
            ERR_LIB("close()", "Failed to close output file");
            return 1;
        }
    }

    delete[] sha256_key_hash;
    delete[] aes_key_sched;
    delete[] buf;
    delete[] ctxs;
    return res;
}

