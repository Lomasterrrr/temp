/*
 * LIBNCSOCK & NESCA4
 *   Сделано от души 2024.
 * Copyright (c) [2024] [lomaster]
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "include/readpkt.h"

const bool read_util_validate_tcp(const u8 *tcpc, unsigned len)
{
  const struct tcp_hdr *tcp = (struct tcp_hdr *) tcpc;
  unsigned hdrlen, optlen;

  hdrlen = tcp->th_off * 4;

  if (hdrlen > len || hdrlen < sizeof(struct tcp_hdr))
    return false;

  tcpc += sizeof(struct tcp_hdr);
  optlen = hdrlen - sizeof(struct tcp_hdr);

#define OPTLEN_IS(expected) do {					\
    if ((expected) == 0 || optlen < (expected) || hdrlen != (expected)) \
      return false;							\
    optlen -= (expected);						\
    tcpc += (expected);							\
  } while(0);
  while (optlen > 1) {
    hdrlen = *(tcpc + 1);
    switch (*tcpc) {
    case 0:
      return true;
    case 1:
      optlen--;
      tcpc++;
      break;
    case 2:
      OPTLEN_IS(4);
      break;
    case 3:
      OPTLEN_IS(3);
      break;
    case 4:
      OPTLEN_IS(2);
      break;
    case 5:
      if (!(hdrlen - 2) || ((hdrlen - 2) % 8))
        return false;
      OPTLEN_IS(hdrlen);
      break;
    case 8:
      OPTLEN_IS(10);
      break;
    case 14:
      OPTLEN_IS(3);
      break;
    default:
      OPTLEN_IS(hdrlen);
      break;
    }
  }

  if (optlen == 1)
    return (*tcpc == 0 || *tcpc == 1);
  assert(optlen == 0);
  return true;
#undef OPTLEN_IS
}

const bool read_util_validate_pkt(const u8 *ipc, unsigned *len)
{
  const struct ip4_hdr *ip = (struct ip4_hdr*)ipc;
  const void *data;
  u32 datalen, iplen;
  u8 hdr;

  if (*len < 1)
    return false;

  if (ip->version == 4) {
    unsigned fragoff, iplen;

    datalen = *len;
    data = read_util_ip4getdata_up(ip, &datalen);
    if (!data)
      return false;

    iplen = ntohs(ip->totlen);

    fragoff = 8 * (ntohs(ip->off) & IP4_OFFMASK);
    if (fragoff)
      return false;

    if (*len > iplen)
      *len = iplen;
    hdr = ip->proto;
  }
  else if (ip->version == 6) {
    const struct ip6_hdr *ip6 = (struct ip6_hdr *) ipc;
    
    datalen = *len;
    data = read_util_ip6getdata(ip6, &datalen, &hdr);
    if (data == NULL)
      return false;
    
    iplen = ntohs(ip6->IP6_PKTLEN);
    if (datalen > iplen)
      *len -= datalen - iplen;
  }
  else
    return false;

  switch (hdr) {
  case IPPROTO_TCP:
    if (datalen < sizeof(struct tcp_hdr))
      return false;
    if (!read_util_validate_tcp((u8 *)data, datalen))
      return false;
    break;
  case IPPROTO_UDP:
    if (datalen < sizeof(struct udp_hdr))
      return false;
    break;
  default:
    break;
  }
  
  return true;
}
