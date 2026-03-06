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

enum {
    /* AES block size, in bytes */
    aes_block_sz = 16
};

struct opts {
    int enc;
    const char *pwd;
    const char *file_in;
    const char *file_out;
};

#if 0
static void cipher(unsigned char *block, unsigned char *key_schedule)
{

}
#endif

int run_enc(const struct opts *opts)
{
    int fd_in;
    int fd_out;
    int res;
    unsigned char buf[aes_block_sz];
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

        /* TODO: Process block */

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

    res = opts_parse(&opts, argc, argv);
    if(res != 0) {
        ERR("Invalid input arguments");
        return 1;
    }

    res = run_enc(&opts);
    if(res != 0) {
        ERR("Failed to process data");
        return 1;
    }

    return 0;
}

