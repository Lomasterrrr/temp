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

int bpf_open(void)
{
  static const char cloning_device[] = "/dev/bpf";
  char device[sizeof "/dev/bpf0000000000"];
  static int no_cloning_bpf = 0;
  int res = -1;
  u32 n = 0;

  if (!no_cloning_bpf &&
      (res = open(cloning_device, O_RDWR)) == -1 &&
      ((errno != EACCES && errno != ENOENT) ||
       (res = open(cloning_device, O_RDONLY)) == -1)) {
    if (errno != ENOENT)
      return res;
    no_cloning_bpf = 1;
  }
  if (no_cloning_bpf) {
    do {
      (void)snprintf(device, sizeof(device), "/dev/bpf%u", n++);
      res = open(device, O_RDWR);
      if (res == -1 && errno == EACCES)
	res = open(device, O_RDONLY);
    } while (res < 0 && errno == EBUSY);
  }
  return res;
}

eth_t *eth_open(const char *device)
{
  struct ifreq ifr;
  eth_t *e = NULL;
  int i;

  e = calloc(1, sizeof(*e));
  if (!e)
    return e;
  if ((e->fd = bpf_open()) < 0) {
    printf("bpf_open\n");
    return (eth_close(e));
  }
  
  memset(&ifr, 0, sizeof(ifr));
  strlcpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));

  if (ioctl(e->fd, BIOCSETIF, &ifr) < 0) {
    printf("BIOCSETIF\n");
    return (eth_close(e));
  }
  
  i = 1;
  if (ioctl(e->fd, BIOCSHDRCMPLT, &i) < 0) {
    printf("BIOCSHDRCMPLT\n");
    return (eth_close(e));
  }
  
  strlcpy(e->device, device, sizeof(e->device));
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

ssize_t eth_send(eth_t *e, const void *buf, size_t len)
{
  return (write(e->fd, buf, len));
}

ssize_t eth_read(eth_t *e, u8 *buf, ssize_t len)
{
  return read(e->fd, buf, len);
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
  eth_t *e = NULL;

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

ssize_t eth_read(eth_t *e, u8 *buf, ssize_t len)
{
  return recv(e->fd, buf, len, 0);
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
