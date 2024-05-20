/*
 * LIBNCSOCK & NESCA4
 *   Сделано от души 2023.
 * Copyright (c) [2023] [lomaster]
 * SPDX-License-Identifier: BSD-3-Clause
*/

#include "include/ip.h"

int ip4_send_raw(int fd, const struct sockaddr_in *dst, const u8 *pkt,
                 u32 pktlen)
{
  struct sockaddr_in sock;
  struct tcp_hdr *tcp;
  struct udp_hdr *udp;
  struct ip4_hdr *ip;
  int res;

  ip = (struct ip4_hdr*)pkt;
  assert(fd >= 0);
  sock = *dst;

  if (pktlen >= 20) {
    if (ip->proto == IPPROTO_TCP && pktlen >= (u32)ip->ihl * 4 + 20) {
      tcp = (struct tcp_hdr*)((u8*)ip + ip->ihl * 4);
      sock.sin_port = tcp->th_dport;
    }
    else if (ip->proto == IPPROTO_UDP && pktlen >= (u32) ip->ihl  * 4 + 8) {
      udp = (struct udp_hdr*)((u8*)ip + ip->ihl * 4);
      sock.sin_port = udp->dstport;
    }
  }

#if (defined(FREEBSD) && (__FreeBSD_version < 1100030)) || BSDI || NETBSD || DEC || MACOSX
  ip->totlen = ntohs(ip->totlen);
  ip->off = ntohs(ip->off);
#endif

  res = sendto(fd, pkt, pktlen, 0, (struct sockaddr*)&sock,
		 (int)sizeof(struct sockaddr_in));

#if (defined(FREEBSD) && (__FreeBSD_version < 1100030)) || BSDI || NETBSD || DEC || MACOSX
  ip->totlen = htons(ip->totlen);
  ip->off = htons(ip->off);
#endif

  return res;
}
