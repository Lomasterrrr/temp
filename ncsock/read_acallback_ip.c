/*
 * LIBNCSOCK & NESCA4
 *   Сделано от души 2024.
 * Copyright (c) [2024] [lomaster]
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "include/readpkt.h"

bool read_acallback_ip(const u8 *pkt, const struct pcap_pkthdr *hdr, int datalink, size_t offset)
{
  const struct ip4_hdr *ip = NULL;
  
  if (hdr->caplen < offset + sizeof(struct ip4_hdr))
    return false;
  ip = (struct ip4_hdr *)(pkt + offset);
  switch (ip->version) {
    case 4:
    case 6:
      break;
    default:
      return false;
  }

  return true;
}
