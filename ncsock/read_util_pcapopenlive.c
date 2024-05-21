/*
 * LIBNCSOCK & NESCA4
 *   Сделано от души 2024.
 * Copyright (c) [2024] [lomaster]
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "include/readpkt.h"

pcap_t *read_util_pcapopenlive(const char *device, int snaplen, int promisc, int ms)
{
  char error[PCAP_ERRBUF_SIZE];
  char dev[128];
  pcap_t *res;

  assert(device);
  strncpy(dev, device, sizeof(dev));
  
  res = pcap_create(dev, error);
  if (!res)
    return NULL;

  if (pcap_set_snaplen(res, snaplen) != 0)
    goto bad;
  if (pcap_set_promisc(res, promisc) != 0)
    goto bad;
  if (pcap_set_timeout(res, ms) != 0)
    goto bad;
#ifdef HAVE_PCAP_SET_IMMEDIATE_MODE
  if (pcap_set_immediate_mode(res, 1) != 0)
    goto bad;  
#endif
  if (pcap_activate(res) < 0)
    goto bad;
  
  return res;
  
 bad:
  pcap_close(res);
  return NULL;
}
