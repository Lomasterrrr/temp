/*
 * LIBNCSOCK & NESCA4
 *   Сделано от души 2023.
 * Copyright (c) [2023] [lomaster]
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "include/readpkt.h"

const void *read_util_ip4getdata_up(const struct ip4_hdr *ip, u32 *len)
{
  u32 hdrlen;
  
  if (*len < 20)
    return NULL;
  hdrlen = ip->ihl * 4;
  if (hdrlen < sizeof(*ip))
    return NULL;
  if (hdrlen > *len)
    return NULL;
  *len -= hdrlen;

  return (char*)ip + hdrlen;
}
