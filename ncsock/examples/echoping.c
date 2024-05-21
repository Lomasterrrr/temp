/*
 * LIBNCSOCK & NESCA4 & ECHOPING
 *   Сделано от души 2023.
 * Copyright (c) [2023] [lomaster]
 * SPDX-License-Identifier: BSD-3-Clause
*/

#include <arpa/inet.h>
#include <stdio.h>
#include <stdnoreturn.h>
#include <string.h>
#include "../include/icmp.h"
#include "../include/readpkt.h"
#include "../include/utils.h"
#include "../include/log.h"

noreturn void usage(char** argv)
{
  printf("Usage: %s [ip] [timeout_ms] [size (max 1400)]\n", argv[0]);
  exit(0);
}

int main(int argc, char** argv)
{
  struct icmp4_hdr *icmph = NULL;
  struct ip4_hdr *ip;
  int fd, i;
  char *src;
  double rtt;
  char* data;
  
  if (argc < 3 + 1)
    usage(argv);

  if (atoi(argv[3]) > 1400)
    usage(argv);

  if (!check_root_perms())
    errx(1, "Only <sudo> run!");

  data = random_str(atoi(argv[3]),
      DEFAULT_DICTIONARY);
  src = ip4_util_strsrc();
    
  pcap_t *p;
  char dev[16];
  u32 pktlen;
  struct abstract_iphdr iphdr;
  const void *datap = NULL;
  
  get_active_interface_name(dev, 16);
  p = read_util_pcapopenlive(dev, 100, 1, 1);
  if (!p)
    return -1;
  read_util_pcapfilter(p, "icmp and dst host %s and src host %s", src, argv[1]);
  
  fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  u32 dst = inet_addr(argv[1]);

  for (i = 1; i <= 10; i++) {
    /* SEND PACKET */
    icmp4_send_pkt(NULL, fd, inet_addr(src), dst, 121, false,
        NULL, 0, i, 0, ICMP4_ECHO, data, strlen(data), 0, false);

    ip = (struct ip4_hdr*)read_ippcap(p, &pktlen, 1e+9, &rtt, NULL, true);
    datap = read_util_ip4getdata(ip, &pktlen, &iphdr);
    if (!datap)
      continue;
    icmph = (struct icmp4_hdr*)datap;
    
    /* READ PACKET */
    if (icmph->type != ICMP4_ECHOREPLY)
      rtt = -1;
      

    /* PRINT INFO */
    printf("ICMPECHO PING [%d pkt]: dst (%s), timeout=%s, payload=%s, rtt=[%0.1f]ms\n",
        i, argv[1], argv[2], argv[3], rtt);

    delayy(300);
  }
  pcap_close(p);

  free(data);
  free(src);
  close(fd);

  return 0;
}

