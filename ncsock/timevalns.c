/*
 * LIBNCSOCK & NESCA4
 *   Сделано от души 2023.
 * Copyright (c) [2023] [lomaster]
 * SPDX-License-Identifier: BSD-3-Clause
*/

#include "include/utils.h"

struct timeval timevalns(long long ns)
{
  struct timeval tv;
  tv.tv_sec = ns / 1000000000LL;
  tv.tv_usec = (ns % 1000000000LL) / 1000;
  return tv;
}
