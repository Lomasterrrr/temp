/*
 * LIBNCSOCK & NESCA4
 *   Сделано от души 2024.
 * Copyright (c) [2024] [lomaster]
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "include/readpkt.h"

const u8 *read_ippcap(pcap_t *p, u32 *pktlen, long long timeout, double *rtt,
                      struct link_header *linknfo, bool validate)
{
  struct pcap_pkthdr *head;
  size_t offset = 0;
  int got_one = 0;  
  int datalink;
  const u8 *pkt;

  if (linknfo)
    memset(linknfo, 0, sizeof(*linknfo));

  if (validate)
    got_one = read_util_pcapread(p, timeout, read_acallback_ip, &pkt, &head, rtt, &datalink, &offset);
  else
    got_one = read_util_pcapread(p, timeout, read_acallback_any, &pkt, &head, rtt, &datalink, &offset);

  if (!got_one) {
    *pktlen = 0;
    return NULL;
  }

  *pktlen = head->caplen - offset;
  pkt += offset;

  if (validate) {
    if (!read_util_validate_pkt(pkt, pktlen)) {
      *pktlen = 0;
      return NULL;
    }
  }

  if (offset && linknfo) {
    linknfo->datalinktype = datalink;
    linknfo->headerlen = offset;
    assert(offset <= MAX_LINK_HEADERSZ);
    memcpy(linknfo->header, pkt - offset, MIN(sizeof(linknfo->header), offset));
  }

  *pktlen = head->caplen - offset;
  return pkt;
}
