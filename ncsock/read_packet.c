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
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>

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

int read_packet(struct readfiler *rf, long long timeoutns, u8 **buffer, size_t *pktlen, double *rtt)
{
  long long start_time;
  struct sockaddr_in6 *dest6 = NULL, source6;
  struct sockaddr_in  *dest = NULL, source;
  u8* read_buffer = *buffer;
  struct timespec sr, er;
  bool fuckyeah = false;
  struct ip6_hdr *iph6;
  int sock;
  struct ip *iph;

  if (rf->ip->ss_family == AF_INET)
    dest = (struct sockaddr_in*)rf->ip;
  else if (rf->ip->ss_family == AF_INET6)
    dest6 = (struct sockaddr_in6*)rf->ip;

  sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (sock == -1)
    return -1;
  socket_util_timeoutns(sock, timeoutns, false, true);
  
  start_time = current_timens();
  get_current_time(&sr);
  for (;;) {
    if (!check_timens(timeoutns, start_time))
      goto fail;
    if ((*pktlen = recv(sock, read_buffer, RECV_BUFFER_SIZE, 0)) == -1)
      goto fail;
    get_current_time(&er);
    if (rf->ip->ss_family == AF_INET) {
      iph = (struct ip*)(read_buffer + sizeof(struct ethhdr));
      memset(&source, 0, sizeof(source));
      source.sin_addr.s_addr = iph->ip_src.s_addr;
      if (source.sin_addr.s_addr == dest->sin_addr.s_addr)
        fuckyeah = true;
    }
    else if (rf->ip->ss_family == AF_INET6) {
      iph6 = (struct ip6_hdr*)(read_buffer + sizeof(struct ethhdr));
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
          if (iph->ip_p != rf->protocol || iph->ip_p != rf->second_protocol)
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
      close(sock);
      return 0;
    }
  }
fail:
  close(sock);
  return -1;
}