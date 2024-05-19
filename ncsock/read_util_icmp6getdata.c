/*
 * LIBNCSOCK & NESCA4
 *   Сделано от души 2023.
 * Copyright (c) [2023] [lomaster]
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "include/readpkt.h"

const void *read_util_icmp6getdata(const struct icmp6_hdr *icmp, u32 *len)
{
  u32 hdrlen;

  if (icmp->type == ICMP6_TIMEXCEED || icmp->type == ICMP6_UNREACH)
    hdrlen = 8;
  if (hdrlen > *len)
    return NULL;
  *len -= hdrlen;

  return (char*)icmp + hdrlen;
}
