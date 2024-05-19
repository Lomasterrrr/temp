/*
 * LIBNCSOCK & NESCA4
 *   Сделано от души 2023.
 * Copyright (c) [2023] [lomaster]
 * SPDX-License-Identifier: BSD-3-Clause
*/

#include "include/eth.h"
#include "include/icmp.h"
#include "include/igmp.h"
#include "include/readpkt.h"

struct ip4_hdr* ext_iphdr(u8 *buf)
{
  struct ip4_hdr *iphdr;
  iphdr = (struct ip4_hdr*)(buf + sizeof(struct eth_hdr));
  return iphdr;
}

struct tcp_hdr* ext_tcphdr(u8 *buf)
{
  struct tcp_hdr *tcphdr;
  tcphdr = (struct tcp_hdr*)(buf + sizeof(struct eth_hdr) + sizeof(struct ip4_hdr));
  return tcphdr;
}

struct udp_hdr* ext_udphdr(u8 *buf)
{
  struct udp_hdr *udphdr;
  udphdr = (struct udp_hdr *)(buf + sizeof(struct eth_hdr) + sizeof(struct ip4_hdr));
  return udphdr;
}

struct icmp4_hdr* ext_icmphdr(u8 *buf)
{
  struct icmp4_hdr *icmphdr;
  icmphdr = (struct icmp4_hdr *)(buf + sizeof(struct eth_hdr) + sizeof(struct ip4_hdr));
  return icmphdr;
}

struct igmp_hdr* ext_igmphdr(u8 *buf)
{
  struct igmp_hdr *igmphdr;
  igmphdr = (struct igmp_hdr *)(buf + sizeof(struct eth_hdr) + sizeof(struct ip4_hdr));
  return igmphdr;
}
