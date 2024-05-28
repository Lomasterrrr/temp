/*
 * LIBNCSOCK & NESCA4
 *   Сделано от души 2023.
 * Copyright (c) [2023] [lomaster]
 * SPDX-License-Identifier: BSD-3-Clause
*/

#include "include/utils.h"

char* get_active_interface_name(char* buffer, size_t len)
{
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *alldevs, *d;
  
  if (pcap_findalldevs(&alldevs, errbuf) == -1)
    return NULL;
  
  for (d = alldevs; d != NULL; d = d->next) {
    if (d->flags & PCAP_IF_UP && !(d->flags & PCAP_IF_LOOPBACK)) {
      if (strlen(d->name) < len) {
	strcpy(buffer, d->name);
	pcap_freealldevs(alldevs);
	return buffer;
      }
      else
	goto fail;
    }
  }
 fail:  
  pcap_freealldevs(alldevs);
  return NULL;
}
