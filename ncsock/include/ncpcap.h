/*
 * LIBNCSOCK & NESCA4
 *   Сделано от души 2024.
 * Copyright (c) [2024] [lomaster]
 * SPDX-License-Identifier: BSD-3-Clause
*/

#ifndef NCPCAP_HEADER
#define NCPCAP_HEADER

#include <endian.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdarg.h>
#include <pcap/pcap.h>

#include "igmp.h"
#include "ip.h"
#include "eth.h"
#include "sctp.h"
#include "arp.h"
#include "tcp.h"
#include "udp.h"
#include "icmp.h"
#include "utils.h"
#include "readpkt.h"

#include "../ncsock-config.h"
#include "sys/types.h"
#include "sys/nethdrs.h"

__BEGIN_DECLS

pcap_t   *ncpcap_openlive(const char *device, int snaplen, int promisc, long long ns);
int       ncpcap_filter(pcap_t *p, const char *bpf, ...);

bool      ncpcap_read(pcap_t *p, long long ns,
		      bool (*accept_callback)(const u8 *, const struct pcap_pkthdr *,
					      int, size_t), struct timeval *rcvd,
		      const u8 **pkt, struct pcap_pkthdr **head,
		      int *datalink, size_t *offset);

const u8 *ncpcap_ipread(pcap_t *p, u32 *pktlen, long long ns, struct timeval *rcvd, struct link_header *linknfo, bool validate);
bool      ncpcap_acallback_any(const u8 *pkt, const struct pcap_pkthdr *hdr, int datalink, size_t offset);
bool      ncpcap_acallback_arp(const u8 *pkt, const struct pcap_pkthdr *hdr, int datalink, size_t offset);
bool      ncpcap_acallback_ip(const u8 *pkt, const struct pcap_pkthdr *hdr, int datalink, size_t offset);

__END_DECLS

#endif
