/*
 * LIBNCSOCK & NESCA4
 *   Сделано от души 2023.
 * Copyright (c) [2023] [lomaster]
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "include/readpkt.h"

void read_util_tracepkt(int pdir, const u8 *pkt, u32 len, double rtt, int detail)
{
  if (rtt)
    printf("%s (%0.2f ms) %s\n",
	   (pdir == 1) ? "SENT" : "RCVD", rtt, read_ippktinfo(pkt, len, detail));
  else
    printf("%s (n/a) %s\n",
	   (pdir == 1) ? "SENT" : "RCVD", read_ippktinfo(pkt, len, detail));
}
