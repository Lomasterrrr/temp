/*
 * LIBNCSOCK & NESCA4
 *   Сделано от души 2023.
 * Copyright (c) [2023] [lomaster]
 * Copyright (c) [2000] Dug Song <dugsong@monkey.org>
 * SPDX-License-Identifier: BSD-3-Clause
*/

#if (defined(FREEBSD) || defined(OPENBSD))
#include "include/eth.h"

#include <sys/param.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#if defined(HAVE_SYS_SYSCTL_H) && defined(HAVE_ROUTE_RT_MSGHDR)
#include <sys/sysctl.h>
#include <net/route.h>
#include <net/if_dl.h>
#endif
#include <net/bpf.h>
#include <net/if.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct eth_handle { int fd; char device[16]; };

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
