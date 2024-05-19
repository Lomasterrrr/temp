/*
 * LIBNCSOCK & NESCA4 & ECHOPING
 *   Сделано от души 2023.
 * Copyright (c) [2023] [lomaster]
 * SPDX-License-Identifier: BSD-3-Clause
*/

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
  struct sockaddr_in dst;
  struct readfiler rf;
  int fd, i;
  char *src;
  double rtt;
  char* data;
  size_t tmp;
  u8 *packet;

  if (argc < 3 + 1)
    usage(argv);

  if (atoi(argv[3]) > 1400)
    usage(argv);

  if (!check_root_perms())
    errx(1, "Only <sudo> run!");

  data = random_str(atoi(argv[3]),
      DEFAULT_DICTIONARY);
  src = ip4_util_strsrc();

  dst.sin_addr.s_addr = inet_addr(argv[1]);
  dst.sin_family = AF_INET;
  rf.ip = (struct sockaddr_storage*)&dst;
  rf.protocol = IPPROTO_ICMP;

  fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (fd == -1)
    return -1;

  for (i = 1; i <= 10; i++) {
    /* SEND PACKET */
    icmp4_send_pkt(NULL, fd, inet_addr(src), dst.sin_addr.s_addr, 121, false,
        NULL, 0, i, 0, ICMP4_ECHO, data, strlen(data), 0, false);

    /* RECV PACKET */
    packet = (u8 *)calloc(RECV_BUFFER_SIZE, sizeof(u8));
    if (read_packet(&rf, atoi(argv[2]), &packet, &tmp, &rtt) != -1)
      icmph = ext_icmphdr(packet);
    free(packet);

    /* READ PACKET */
    if (icmph && icmph->type != ICMP4_ECHOREPLY)
      rtt = -1;

    /* PRINT INFO */
    printf("ICMPECHO PING [%d pkt]: dst (%s), timeout=%s, payload=%s, rtt=[%0.1f]ms\n",
        i, argv[1], argv[2], argv[3], rtt);

    delayy(300);
  }

  free(data);
  free(src);
  close(fd);

  return 0;
}

