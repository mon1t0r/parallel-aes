#ifndef PARALLEL_AES_PKCS7_H
#define PARALLEL_AES_PKCS7_H

#ifdef __cplusplus
extern "C" {
#endif

/* PKCS#7 padding add implementation */
void pkcs7_pad(unsigned char *buf, unsigned int sz_has, unsigned int sz_full);

/* PKCS#7 get existing padding implementation */
unsigned int pkcs7_get_pad(unsigned char *buf, unsigned int sz_full);

#ifdef __cplusplus
}
#endif

#endif

