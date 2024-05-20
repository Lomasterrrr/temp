/*
 * LIBNCSOCK & NESCA4
 *   Сделано от души 2023.
 * Copyright (c) [2023] [lomaster]
 * Copyright (c) [2000] Dug Song <dugsong@monkey.org>
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "include/eth.h"

#if (defined(IS_BSD)) /* BSD SYSTEMS */
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

int bpf_bind(eth_t *e)
{
  int status;
#ifdef LIFNAMSIZ
  struct lifreq ifr;
  const char *ifname = e->device;
  if (strlen(ifname) >= sizeof(ifr.lifr_name))
    return -1;
  (void)strlcpy(ifr.lifr_name, ifname, sizeof(ifr.lifr_name));
  status = ioctl(e->fd, BIOCSETLIF, (caddr_t)&ifr);
#else
  struct ifreq ifr;
  if (strlen((char*)e->device) >= sizeof(ifr.ifr_name))
    return -1;
  (void)strlcpy(ifr.ifr_name, (char*)e->device, sizeof(ifr.ifr_name));
  status = ioctl(e->fd, BIOCSETIF, (caddr_t)&ifr);
#endif
  if (status < 0)
    return -1;
  return 0;
}

int bpf_settimeout(eth_t *e, long long timeoutns)
{
  struct timeval tv;
  
  if (timeoutns < 0)
    return -1;
  
  tv.tv_sec = timeoutns / 1000000000LL;
  tv.tv_usec = (timeoutns % 1000000000LL) / 1000;

  return (ioctl(e->fd, BIOCSRTIMEOUT, (caddr_t)&tv));
}

int bpf_setbuf(eth_t *e, size_t len)
{
  if (len > 0) {
    if (ioctl(e->fd, BIOCSBLEN, (caddr_t)&len) < 0)
      return -1;
  }
  return 0;
}

int bpf_initfilter(eth_t *e)
{
  struct bpf_insn total_insn;
  struct bpf_program total_prog;

  total_insn.code = (u16)(BPF_RET | BPF_K);
  total_insn.jt = 0;
  total_insn.jf = 0;
  total_insn.k = MAX_SNAPLEN;

  total_prog.bf_len = 1;
  total_prog.bf_insns = &total_insn;

  return (ioctl(e->fd, BIOCSETF, (caddr_t)&total_prog));
}

eth_t *eth_open(const char *device)
{
  eth_t *e;
  e = calloc(1, sizeof(*e));
  if (!e)
    return e;
  
  if ((e->fd = bpf_open()) < 0)
    return (eth_close(e));

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
  ssize_t res;
  
  res = write(e->fd, buf, len);
  if (res == -1 && errno == EAFNOSUPPORT) {
    int i = 1;
    if (ioctl(e->fd, BIOCSHDRCMPLT, &i) < 0)
      return res;
    res = write(e->fd, buf, len);
  }
  
  return res;
}

ssize_t eth_read(eth_t *e, u8 *buf, ssize_t len)
{
  ssize_t res;
  res = read(e->fd, buf, len);
  if (res == -1 && errno == EINVAL) {
    if (lseek(e->fd, 0L, SEEK_CUR) + len < 0) {
      (void)lseek(e->fd, 0L, SEEK_SET);
      res = read(e->fd, buf, len);
    }
  }
  
  return res;
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
