/*
 * LIBNCSOCK & NESCA4
 *   Сделано от души 2023.
 * Copyright (c) [2023] [lomaster]
 * SPDX-License-Identifier: BSD-3-Clause

 */

#include "include/readpkt.h"

void read_util_tcpoptinfo(u8 *optp, int len, char *result, int bufsize)
{
  assert(optp);
  assert(result);
  
  u32 tmpword1, tmpword2, i;
  u16 tmpshort;
  char *p, ch;
  int opcode;
  u8 *q;

  p = result;
  *p = '\0';
  q = optp;
  ch = '<';

  while (len > 0 && bufsize > 2) {
    snprintf(p, bufsize, "%c", ch);
    bufsize--;
    p++;
    opcode = *q++;
    if (!opcode) {
      snprintf(p, bufsize, "eol");
      bufsize -= strlen(p);
      p += strlen(p);
      len--;
    }
    else if (opcode == 1) {
      snprintf(p, bufsize, "nop"); 
      bufsize -= strlen(p);
      p += strlen(p);
      len--;
    }
    else if (opcode == 2) {
      if (len < 4)
        break;
      q++;
      memcpy(&tmpshort, q, 2);
      snprintf(p, bufsize, "mss %hu", (u16) ntohs(tmpshort));
      bufsize -= strlen(p);
      p += strlen(p);
      q += 2;
      len -= 4;
    }
    else if (opcode == 3) {
      if (len < 3)
        break;
      q++;
      snprintf(p, bufsize, "wscale %u", *q);
      bufsize -= strlen(p);
      p += strlen(p);
      q++;
      len -= 3;
    }
    else if (opcode == 4) {
      if (len < 2)
        break;
      snprintf(p, bufsize, "sackOK");
      bufsize -= strlen(p);
      p += strlen(p);
      q++;
      len -= 2;
    }
    else if (opcode == 5) {
      unsigned sackoptlen = *q;
      if ((unsigned) len < sackoptlen)
        break;
      if (sackoptlen < 2)
        break;
      q++;
      if ((sackoptlen - 2) == 0 || ((sackoptlen - 2) % 8 != 0)) {
        snprintf(p, bufsize, "malformed sack");
        bufsize -= strlen(p);
        p += strlen(p);
      }
      else {
        snprintf(p, bufsize, "sack %d ", (sackoptlen - 2) / 8);
        bufsize -= strlen(p);
        p += strlen(p);
        for (i = 0; i < sackoptlen - 2; i += 8) {
          memcpy(&tmpword1, q + i, 4);
          memcpy(&tmpword2, q + i + 4, 4);
          snprintf(p, bufsize, "{%u:%u}", tmpword1, tmpword2);
          bufsize -= strlen(p);
          p += strlen(p);
        }
      }

      q += sackoptlen - 2;
      len -= sackoptlen;
    }
    else if (opcode == 8) {
      if (len < 10)
        break;
      q++;
      memcpy(&tmpword1, q, 4);
      memcpy(&tmpword2, q + 4, 4);
      snprintf(p, bufsize, "timestamp %lu %lu", (unsigned long) ntohl(tmpword1),
               (unsigned long) ntohl(tmpword2));
      bufsize -= strlen(p);
      p += strlen(p);
      q += 8;
      len -= 10;
    }
    ch = ',';
  }
  if (len > 0) {
    *result = '\0';
    return;
  }

  snprintf(p, bufsize, ">");
}
