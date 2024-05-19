/*
 * LIBNCSOCK & NESCA4
 *   Сделано от души 2023.
 * Copyright (c) [2023] [lomaster]
 * SPDX-License-Identifier: BSD-3-Clause
*/

#include "include/tcp.h"

struct tcp_flags tcp_util_getflags(u8 flags)
{
  struct tcp_flags tf;
  
  tf.syn = (flags & TCP_FLAG_SYN) ? 1 : 0;
  tf.ack = (flags & TCP_FLAG_ACK) ? 1 : 0;
  tf.fin = (flags & TCP_FLAG_FIN) ? 1 : 0;
  tf.rst = (flags & TCP_FLAG_RST) ? 1 : 0;
  tf.urg = (flags & TCP_FLAG_URG) ? 1 : 0;
  tf.psh = (flags & TCP_FLAG_PSH) ? 1 : 0;
  tf.cwr = (flags & TCP_FLAG_CWR) ? 1 : 0;
  tf.ece = (flags & TCP_FLAG_ECE) ? 1 : 0;
  
  return tf;
}
