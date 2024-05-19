/*
 * LIBNCSOCK & NESCA4
 *   Сделано от души 2023.
 * Copyright (c) [2023] [lomaster]
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "include/readpkt.h"

#define ip6_is_extension_header(type)                                          \
  ((type == IPPROTO_HOPOPTS) || (type == IPPROTO_DSTOPTS) ||                   \
   (type == IPPROTO_ROUTING) || (type == IPPROTO_FRAGMENT))

#define ip6_is_upperlayer(type)                                                \
  ((type == IPPROTO_NONE) || (type == IPPROTO_TCP) || (type == IPPROTO_UDP) || \
   (type == IPPROTO_ICMP) || (type == IPPROTO_ICMPV6) ||                       \
   (type == IPPROTO_SCTP))

const void *read_util_getip6data_pr(const struct ip6_hdr *ip6, u32 *len, u8 *nxt,
                          bool upperlayer_only)
{
  const unsigned char *p, *end;
  if (*len < sizeof(*ip6))
    return NULL;
  
  p = (unsigned char *) ip6;
  end = p + *len;
  *nxt = ip6->IP6_NXT;
  p += sizeof(*ip6);
  
  while (p < end && ip6_is_extension_header(*nxt)) {
    if (p + 2 > end)
      return NULL;
    *nxt = *p;
    p += (*(p + 1) + 1) * 8;
  }

  *len = end - p;
  if (upperlayer_only && !ip6_is_upperlayer(*nxt))
    return NULL;
  
  return (char*)p; 
}
