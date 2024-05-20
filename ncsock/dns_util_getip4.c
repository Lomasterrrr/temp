/*
 * LIBNCSOCK & NESCA4
 *   Сделано от души 2023.
 * Copyright (c) [2023] [lomaster]
 * SPDX-License-Identifier: BSD-3-Clause
*/

#include "include/dns.h"

void dns_util_getip4(const char* dst, int srcport, long long timeoutns, char* dnsbuf, size_t buflen)
{
  struct in_addr addr;
  int sock, res;
  char host[NI_MAXHOST];
  struct sockaddr_in sa;

  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;

  if (inet_pton(AF_INET, dst, &addr) != 1)
    goto fail;

  sa.sin_addr = addr;
  sa.sin_port = htons(srcport);

  sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock == -1)
    goto fail;
  socket_util_timeoutns(sock, timeoutns, true, true);

  res = getnameinfo((struct sockaddr*)&sa, sizeof(sa), host, sizeof(host), NULL, 0, NI_NAMEREQD);
  close(sock);
  if (res < 0)
    goto fail;

  strncpy(dnsbuf, host, buflen);
  dnsbuf[buflen - 1] = '\0';

  return;
fail:
  strncpy(dnsbuf, "n/a", buflen);
  dnsbuf[buflen - 1] = '\0';
  return;
}
