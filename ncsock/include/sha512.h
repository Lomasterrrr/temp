/*
 * LIBNCSOCK & NESCA4
 *   Сделано от души 2023.
 * Copyright (c) [2023] [lomaster]
 * SPDX-License-Identifier: BSD-3-Clause
*/

#ifndef NOTGNU_SHA512_H
#define NOTGNU_SHA512_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../ncsock-config.h"
#include "sys/types.h"

struct sha512_ctx
{
  u64 H[8];
  union
  {
    #if WORDSIZE == 64
      #define USE_TOTAL128
      u32 total128 __attribute__ ((__mode__ (TI)));
    #endif
    #if defined(LITTLE_ENDIAN_SYSTEM)
      #define TOTAL128_low 1
      #define TOTAL128_high 0
    #else
       #define TOTAL128_low 0
       #define TOTAL128_high 1
    #endif
    u64 total[2];
  };
  u64 buflen;
  union
  {
    char buffer[256];
    u64 buffer64[32];
  };
};

__BEGIN_DECLS

/* encrypt buf to md5 (void) */
void *sha512(const void *buf, size_t buflen);

/* encrypt buf to md5 string (char) */
char *sha512str(const void *buf, size_t buflen);

void sha512_init_ctx(struct sha512_ctx *ctx);
void sha512_process_bytes(const void *buffer, size_t len, struct sha512_ctx *ctx);
void sha512_process_block(const void *buffer, size_t len, struct sha512_ctx *ctx);
void *sha512_finish_ctx(struct sha512_ctx *ctx, void *resbuf);

__END_DECLS

#endif

