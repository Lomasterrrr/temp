/*
 * LIBNCSOCK & NESCA4
 *   Сделано от души 2023.
 * Copyright (c) [2023] [lomaster]
 * Copyright (c) [2000] Dug Song <dugsong@monkey.org>
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "include/eth.h"

#if (defined(IS_BSD))
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct eth_handle { int fd; char device[16]; };
int eth_fd(eth_t *e) {
  return e->fd;
}

eth_t *eth_open(const char *device)
{
  struct ifreq ifr;
  char file[32];
  eth_t *e;
  int i;
  
  if ((e = calloc(1, sizeof(*e))) != NULL) {
    for (i = 0; i < 128; i++) {
      snprintf(file, sizeof(file), "/dev/bpf%d", i);
      e->fd = open(file, O_RDWR);
      if (e->fd != -1 || errno != EBUSY)
	break;
    }
    if (e->fd < 0)
      return (eth_close(e));
    
    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
    
    if (ioctl(e->fd, BIOCSETIF, (char *)&ifr) < 0)
      return (eth_close(e));
    strlcpy(e->device, device, sizeof(e->device));
  }
  return (e);
}

eth_t *eth_close(eth_t *e)
{
  if (e != NULL) {
    if (e->fd >= 0)
      close(e->fd);
    free(e);
  }
  return (NULL);
}

ssize_t eth_send(eth_t *e, const void *buf, size_t len) {
  return (write(e->fd, buf, len));
}
#endif

#if defined(IS_LINUX)
#include "include/sys/debianfix.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <stdbool.h>

struct eth_handle { int fd; struct ifreq ifr; struct sockaddr_ll sll; };

int eth_fd(eth_t *e) {
  return e->fd;
}

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
