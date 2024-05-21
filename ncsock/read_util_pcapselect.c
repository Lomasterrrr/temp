/*
 * LIBNCSOCK & NESCA4
 *   Сделано от души 2024.
 * Copyright (c) [2024] [lomaster]
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "include/readpkt.h"

int read_util_pcapselect(pcap_t *p, long long timeout)
{
  struct timeval t;
  int fd, ret;
  fd_set rfds;

  t = timevalns(timeout);
  if ((fd = my_pcap_get_selectable_fd(p)) == -1)
    return -1;

  FD_ZERO(&rfds);
  checked_fd_set(fd, &rfds);

  ret = select(fd + 1, &rfds, NULL, NULL, &t);
  return ret;
}
