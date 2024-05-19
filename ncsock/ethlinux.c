/*
 * LIBNCSOCK & NESCA4
 *   Сделано от души 2023.
 * Copyright (c) [2023] [lomaster]
 * Copyright (c) [2000] Dug Song <dugsong@monkey.org>
 * SPDX-License-Identifier: BSD-3-Clause
*/

#if defined(__linux)
#include "include/eth.h"
#include "include/debianfix.h"

#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/cdefs.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <time.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#if __GLIBC__ >= 2 && __GLIBC_MINOR >= 1
  #include <netpacket/packet.h>
  #include <net/ethernet.h>
#else
  #include <asm/types.h>
  #include <linux/if_packet.h>
  #include <linux/if_ether.h>
#endif
#include <net/if.h>
#include <bits/wordsize.h>

struct eth_handle { int fd; struct ifreq ifr; struct sockaddr_ll sll; };

eth_t *eth_open(const char *device)
{
  eth_t *e;

  e = calloc(1, sizeof(*e));
  if (!e)
    return e;

  if ((e->fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    return (eth_close(e));

  _strlcpy(e->ifr.ifr_name, device, sizeof(e->ifr.ifr_name));
  if (ioctl(e->fd, SIOCGIFINDEX, &e->ifr) < 0)
    return (eth_close(e));

  e->sll.sll_family = AF_PACKET;
  e->sll.sll_ifindex = e->ifr.ifr_ifindex;

  return e;
}

ssize_t eth_send(eth_t *e, const void *buf, size_t len)
{
  struct eth_hdr *eth;

  eth = (struct eth_hdr*)buf;
  e->sll.sll_protocol = eth->type;

  return (sendto(e->fd, buf, len, 0,
        (struct sockaddr*)&e->sll, sizeof(e->sll)));
}

eth_t *eth_close(eth_t *e)
{
  if (e) {
    if (e->fd >= 0)
      close(e->fd);
    free(e);
  }
  return NULL;
}
#endif
