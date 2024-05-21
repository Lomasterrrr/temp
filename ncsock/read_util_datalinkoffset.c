/*
 * LIBNCSOCK & NESCA4
 *   Сделано от души 2024.
 * Copyright (c) [2024] [lomaster]
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "include/readpkt.h"

const int read_util_datalinkoffset(int datalink)
{
  int offset = -1;
  
  switch (datalink) {
  case DLT_EN10MB:
    offset = ETH_HDR_LEN;
    break;
  case DLT_IEEE802:
    offset = 22;
    break;
#ifdef DLT_LOOP
  case DLT_LOOP:
#endif
  case DLT_NULL:
    offset = 4;
    break;
  case DLT_SLIP:
#ifdef DLT_SLIP_BSDOS
  case DLT_SLIP_BSDOS:
#endif
#if defined(IS_BSD)
    offset = 16;
#else
    offset = 24;
#endif
    break;
  case DLT_PPP:
#ifdef DLT_PPP_BSDOS
  case DLT_PPP_BSDOS:
#endif
#ifdef DLT_PPP_SERIAL
  case DLT_PPP_SERIAL:
#endif
#ifdef DLT_PPP_ETHER
  case DLT_PPP_ETHER:
#endif
#if defined(IS_BSD)
    offset = 4;
#else
#ifdef SOLARIS
    offset = 8;
#else
    offset = 24;
#endif
#endif
    break;
  case DLT_RAW:
    offset = 0;
    break;
  case DLT_FDDI:
    offset = 21;
    break;
#ifdef DLT_ENC
  case DLT_ENC:
    offset = 12;
    break;
#endif
#ifdef DLT_LINUX_SLL
  case DLT_LINUX_SLL:
    offset = 16;
    break;
#endif
#ifdef DLT_IPNET
  case DLT_IPNET:
    offset = 24;
    break;
#endif
  default:
    offset = -1;
    break;
  }
  return offset;
}
