#include <string.h>

#include "pkcs7.h"

/* PKCS#7 Spec: https://datatracker.ietf.org/doc/html/rfc5652#section-6.3 */

void pkcs7_pad(unsigned char *buf, unsigned int sz_has, unsigned int sz_full)
{
    unsigned char padding;

    /* Determine padding */
    padding = sz_full - (sz_has % sz_full);

    /* Fill padded space with padding value */
    memset(buf + sz_has, padding, sz_full - sz_has);
}

unsigned int pkcs7_get_pad(unsigned char *buf, unsigned int sz_full)
{
    return buf[sz_full - 1];
}

