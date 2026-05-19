#ifndef PARALLEL_AES_ROT_H
#define PARALLEL_AES_ROT_H

/* General rotate word functions */
#define ROTW_R(x, b) \
   (((x) >> b) | ((x) << (32 - (b))))
#define ROTW_L(x, b) \
    (((x) << b) | ((x) >> (32 - (b))))

#endif

