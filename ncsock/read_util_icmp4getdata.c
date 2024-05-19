/*
 * LIBNCSOCK & NESCA4
 *   Сделано от души 2023.
 * Copyright (c) [2023] [lomaster]
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "include/readpkt.h"

const void *read_util_icmp4getdata(const struct icmp4_hdr *icmp, u32 *len)
{
  u32 hdrlen;

  if (icmp->type == ICMP4_TIME_EXCEEDED ||
      icmp->type == ICMP4_DEST_UNREACH)
    hdrlen = 8;
  if (hdrlen > *len)
    return NULL;
  *len -= hdrlen;

  return (char*)icmp + hdrlen;
}
