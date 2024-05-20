/*
 * LIBNCSOCK & NESCA4
 *   Сделано от души 2024.
 * Copyright (c) [2024] [lomaster]
 * SPDX-License-Identifier: BSD-3-Clause
*/

#ifndef DNS_HEADER
#define DNS_HEADER

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "socket.h"
  
#include "../ncsock-config.h"
#include "sys/types.h"
#include "sys/nethdrs.h"

__BEGIN_DECLS

void dns_util_getip4(const char* dst, int srcport, long long timeoutns, char* dnsbuf, size_t buflen);
void dns_util_getip6(const char* dst, int srcport, char* dnsbuf, size_t buflen);

#define THIS_IS_DNS 0
#define THIS_IS_IP4 1
int dns_or_ip(const char* node);

__END_DECLS

#endif
