/*
 * LIBNCSOCK & NESCA4
 *   Сделано от души 2024.
 * Copyright (c) [2024] [lomaster]
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "include/readpkt.h"

bool read_acallback_any(const u8 *pkt, const struct pcap_pkthdr *hdr, int datalink, size_t offset) {
  return true;
}
