/*
 * LIBNCSOCK & NESCA4
 *   Сделано от души 2023.
 * Copyright (c) [2023] [lomaster]
 * SPDX-License-Identifier: BSD-3-Clause
*/

#include "include/utils.h"

char* get_active_interface_name(char* buffer, size_t len)
{
  struct ifaddrs *ifaddr, *ifa;

  if (getifaddrs(&ifaddr) == -1)
    return NULL;
  for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr == NULL || (ifa->ifa_flags & IFF_UP) == 0)
      continue;
    if ((ifa->ifa_flags & IFF_LOOPBACK) == 0 && 
        (ifa->ifa_addr->sa_family == AF_INET || ifa->ifa_addr->sa_family == AF_INET6)) {
      if (strlen(ifa->ifa_name) < len) {
        strcpy(buffer, ifa->ifa_name);
        freeifaddrs(ifaddr);
        return buffer;
      }
      else {
        freeifaddrs(ifaddr);
        return NULL;
      }
    }
  }
  freeifaddrs(ifaddr);
  return NULL;
}
