/*
 * LIBNCSOCK & NESCA4
 *   Сделано от души 2023.
 * Copyright (c) [2023] [lomaster]
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "include/readpkt.h"

const void *read_util_getip4data_pr(const void *pkt, u32 *len, struct abstract_iphdr *hdr, bool upperlayer_only)
{
  const struct ip4_hdr *ip;
  ip = (struct ip4_hdr *)pkt;
  
  if (*len >= 20 && ip->version == 4) {
    struct sockaddr_in *sin;
    hdr->version = 4;
    sin = (struct sockaddr_in *) &hdr->src;
    memset(&hdr->src, 0, sizeof(hdr->src));
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = ip->src;

    sin = (struct sockaddr_in *) &hdr->dst;
    memset(&hdr->dst, 0, sizeof(hdr->dst));
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = ip->dst;

    hdr->proto = ip->proto;
    hdr->ttl = ip->ttl;
    hdr->ipid = ntohs(ip->id);
    return read_util_ip4getdata_up(ip, len);
  }
  else if (*len >= 40 && ip->version == 6) {
    const struct ip6_hdr *ip6 = (struct ip6_hdr*) ip;
    struct sockaddr_in6 *sin6;
    hdr->version = 6;
    sin6 = (struct sockaddr_in6 *) &hdr->src;
    memset(&hdr->src, 0, sizeof(hdr->src));
    sin6->sin6_family = AF_INET6;
    memcpy(&sin6->sin6_addr, &ip6->ip6_src, IP6_ADDR_LEN);

    sin6 = (struct sockaddr_in6 *) &hdr->dst;
    memset(&hdr->dst, 0, sizeof(hdr->dst));
    sin6->sin6_family = AF_INET6;
    memcpy(&sin6->sin6_addr, &ip6->ip6_dst, IP6_ADDR_LEN);

    hdr->ttl = ip6->IP6_HLIM;
    hdr->ipid = ntohl(ip6->IP6_FLOW & IP6_FLOWLABEL_MASK);
    return read_util_getip6data_pr(ip6, len, &hdr->proto, upperlayer_only);
  }
  return NULL;
}
