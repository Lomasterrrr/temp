/*
 * LIBNCSOCK & NESCA4
 *   Сделано от души 2024.
 * Copyright (c) [2024] [lomaster]
 * SPDX-License-Identifier: BSD-3-Clause
*/

#include "include/ncpcap.h"
#include "include/utils.h"

pcap_t *ncpcap_openlive(const char *device, int snaplen, int promisc, long long ns)
{
  char errbuf[PCAP_ERRBUF_SIZE];
  char dev[512];
  pcap_t *res;
  
  if (!device)
    get_active_interface_name(dev, sizeof(dev));
  else {
    strncpy(dev, device, sizeof(dev) - 1);
    dev[sizeof(dev) - 1] = '\0';
  }

  res = pcap_open_live(dev, snaplen, promisc, to_ms(ns), errbuf);
  if (res && pcap_setnonblock(res, 1, errbuf) == -1) {
    pcap_close(res);
    return NULL;
  }

  return res;
}

bool ncpcap_read(pcap_t *p, long long ns, bool (*accept_callback)(const u8 *,const struct pcap_pkthdr *, int, size_t),
		 struct timeval *rcvd, const u8 **pkt, struct pcap_pkthdr **head, int *datalink, size_t *offset)
{
  struct timeval start, current;
  struct pcap_pkthdr tmphdr;
  double elapsed; 
  int ioffset;
  
  if (!p)
    return false;
  if (ns < 0)
    ns = 0;
  
  if ((*datalink = pcap_datalink(p)) < 0)
    return false;
  ioffset = read_util_datalinkoffset(*datalink);
  if (ioffset < 0)
    return false;
  *offset = (u32)ioffset;
  
  gettimeofday(&start, NULL);
  for (;;) {
    gettimeofday(&current, NULL);
    elapsed = (current.tv_sec - start.tv_sec) * 1000000000LL + (current.tv_usec - start.tv_usec) * 1000LL;
    if (elapsed >= ns)
      return false;
    *pkt = pcap_next(p, &tmphdr);
    if (*pkt) {
      *head = &tmphdr;
      if (accept_callback(*pkt, *head, *datalink, *offset)) {
	rcvd->tv_sec = (*head)->ts.tv_sec;
	rcvd->tv_usec = (*head)->ts.tv_usec;
	assert((*head)->ts.tv_sec);
	return true;
      }
    }
  }
  return false;
}

const u8 *ncpcap_ipread(pcap_t *p, u32 *pktlen, long long ns, struct timeval *rcvd, struct link_header *linknfo, bool validate)
{
  struct pcap_pkthdr *head = NULL;;
  int got_one = 0, datalink;
  const u8 *pkt = NULL;
  size_t offset = 0;

  if (linknfo)
    memset(linknfo, 0, sizeof(*linknfo));

  if (validate)
    got_one = ncpcap_read(p, ns, ncpcap_acallback_ip, rcvd, &pkt, &head, &datalink, &offset);
  else
    got_one = ncpcap_read(p, ns, ncpcap_acallback_any, rcvd, &pkt, &head, &datalink, &offset);
  if (!got_one)
    goto err;

  *pktlen = head->caplen - offset;
  pkt += offset;

  if (validate)
    if (!read_util_validate_pkt(pkt, pktlen))
      goto err;

  if (offset && linknfo) {
    linknfo->datalinktype = datalink;
    linknfo->headerlen = offset;
    assert(offset <= MAX_LINK_HEADERSZ);
    memcpy(linknfo->header, pkt - offset, MIN(sizeof(linknfo->header), offset));
  }

  *pktlen = head->caplen - offset;
  return pkt;
  
 err:
  *pktlen = 0;
  return NULL;
}

int ncpcap_filter(pcap_t *p, const char *bpf, ...)
{
  struct bpf_program fcode;
  char buf[3072];
  va_list ap;
  int size;

  va_start(ap, bpf);
  size = vsnprintf(buf, sizeof(buf), bpf, ap);
  va_end(ap);
  if (size >= (int)sizeof(buf))
    return -1;

  if (pcap_compile(p, &fcode, buf, 1, PCAP_NETMASK_UNKNOWN) < 0)
    return -1;
  if (pcap_setfilter(p, &fcode) < 0)
    return -1;
  
  pcap_freecode(&fcode);
  return 0;
}

bool ncpcap_acallback_any(const u8 *pkt, const struct pcap_pkthdr *hdr, int datalink, size_t offset)
{
  return true;
}

bool ncpcap_acallback_arp(const u8 *pkt, const struct pcap_pkthdr *hdr, int datalink, size_t offset)
{
  if (hdr->caplen < offset + 28)
    return false;
  if (memcmp(pkt + offset, "\x00\x01\x08\x00\x06\x04\x00\x02", 8) != 0)
    return false;

  if (datalink == DLT_EN10MB)
    return ntohs(*((u16 *) (pkt + 12))) == ETH_TYPE_ARP;
  else if (datalink == DLT_LINUX_SLL)
    return ntohs(*((u16 *) (pkt + 2))) == ARP_HRD_ETH &&
      ntohs(*((u16 *) (pkt + 4))) == 6 &&
      ntohs(*((u16 *) (pkt + 14))) == ETH_TYPE_ARP;
  
  return false;
}

bool ncpcap_acallback_ip(const u8 *pkt, const struct pcap_pkthdr *hdr, int datalink, size_t offset)
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


