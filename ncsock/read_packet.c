/*
 * LIBNCSOCK & NESCA4
 *   Сделано от души 2023.
 * Copyright (c) [2023] [lomaster]
 * SPDX-License-Identifier: BSD-3-Clause
*/

#include "include/eth.h"
#include "include/readpkt.h"
#include "include/ip.h"
#include "include/utils.h"
#include "include/socket.h"
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>

static long long current_timens(void)
{
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return now.tv_sec * 1000000000LL + now.tv_nsec;
}

static bool check_timens(long long timeoutns, long long startns)
{
  long long current_time, elapsed_time;
  current_time = current_timens();
  elapsed_time = current_time - startns;
  if (elapsed_time >= timeoutns)
    return false;
  return true;
}

void get_current_time(struct timespec* ts) {
  clock_gettime(CLOCK_MONOTONIC, ts);
}

double calculate_duration_ms(struct timespec *start, struct timespec *end)
{
  if (!start || !end)
    return -1;
  return ((end->tv_sec - start->tv_sec) * 1000.0)
    + ((end->tv_nsec - start->tv_nsec) / 1000000.0);
}

int read_packet(eth_t *eth, struct readfiler *rf, long long timeoutns, u8 **buffer, size_t *pktlen, double *rtt)
{
  long long start_time;
  struct sockaddr_in6 *dest6 = NULL, source6;
  struct sockaddr_in  *dest = NULL, source;
  u8* read_buffer = NULL;
  struct timespec sr, er;
  bool fuckyeah = false;
  struct ip6_hdr *iph6;
  struct ip4_hdr *iph;
  char device[16];
  int buflen;

  if (rf->ip->ss_family == AF_INET)
    dest = (struct sockaddr_in*)rf->ip;
  else if (rf->ip->ss_family == AF_INET6)
    dest6 = (struct sockaddr_in6*)rf->ip;

  if (!eth) {
    get_active_interface_name(device, 16);
    eth = eth_open(device);
    if (!eth)
      return -1;
  }
  
#if defined (IS_BSD)
  if ((bpf_setbuf(eth, RECV_BUFFER_SIZE)) == -1)
    goto fail;
  if ((bpf_bind(eth)) == -1)
    goto fail;
  if ((bpf_settimeout(eth, timeoutns)) == -1)
    goto fail;
  if ((bpf_biopromisc(eth)) == -1)
    goto fail;
  if ((buflen = bpf_getbuflen(eth)) == -1)
    goto fail;
  read_buffer = realloc(*buffer, buflen);
  if (!read_buffer)
    goto fail;
  if ((bpf_initfilter(eth)) == -1)
    goto fail;
#else
  socket_util_timeoutns(eth_fd(eth), timeoutns, false, true);
  read_buffer = *buffer;
  buflen = RECV_BUFFER_SIZE;
#endif
  printf("buflen=%d\n", buflen);

  start_time = current_timens();
  get_current_time(&sr);
  
  for (;;) {
    if (!check_timens(timeoutns, start_time))
      goto fail;
    if ((*pktlen = eth_read(eth, read_buffer, buflen)) == -1)
      goto fail;
    printf("[+]: READ!! (%ld)\n", *pktlen);
    get_current_time(&er);
    if (rf->ip->ss_family == AF_INET) {
      iph = (struct ip4_hdr*)(read_buffer + sizeof(struct eth_hdr));
      memset(&source, 0, sizeof(source));
      source.sin_addr.s_addr = iph->src;
      if (source.sin_addr.s_addr == dest->sin_addr.s_addr)
        fuckyeah = true;
    }
    else if (rf->ip->ss_family == AF_INET6) {
      iph6 = (struct ip6_hdr*)(read_buffer + sizeof(struct eth_hdr));
      memset(&source6, 0, sizeof(source6));
      memcpy(&source6.sin6_addr.s6_addr, &iph6->ip6_src, sizeof(struct in6_addr));
      if (memcmp(&source6.sin6_addr, &dest6->sin6_addr, sizeof(struct in6_addr)) == 0)
        fuckyeah = true;
    }
    if (!fuckyeah) {
      if (!check_timens(timeoutns, start_time))
	goto fail;
      if (rf->protocol) {
        if (rf->ip->ss_family == AF_INET)
          if (iph->proto != rf->protocol || iph->proto != rf->second_protocol)
            continue;
        if (rf->ip->ss_family == AF_INET6)
          if (iph6->ip6_ctlun.ip6_un1.ip6_un1_nxt != rf->protocol || iph6->ip6_ctlun.ip6_un1.ip6_un1_nxt != rf->second_protocol)
            continue;
      }
      continue;
    }
    else {
      *rtt = calculate_duration_ms(&sr, &er);
      *buffer = read_buffer;
      eth_close(eth);
      return 0;
    }
  }
fail:
  eth_close(eth);
  return -1;
}
