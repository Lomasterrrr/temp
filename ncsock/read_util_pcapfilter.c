/*
 * LIBNCSOCK & NESCA4
 *   Сделано от души 2024.
 * Copyright (c) [2024] [lomaster]
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "include/readpkt.h"

int read_util_pcapfilter(pcap_t *p, const char *bpf, ...)
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
