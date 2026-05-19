#ifndef PARALLEL_AES_ERR_H
#define PARALLEL_AES_ERR_H

#define ERR(str) fprintf(stderr, "%s\n", str)
#define ERR_LIB(call_name, str) \
    do {                        \
        perror(call_name);      \
        ERR(str);               \
    } while(0)

#endif

