/*
 * LIBNCSOCK & NESCA4
 *   Сделано от души 2024.
 * Copyright (c) [2024] [lomaster]
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "include/readpkt.h"

bool read_util_pcapread(pcap_t *p, long long timeout, bool (*accept_callback)(const u8 *,const struct pcap_pkthdr *, int,  size_t),
		       const u8 **pkt, struct pcap_pkthdr **head, double *rtt, int *datalink, size_t *offset)
{
  struct timeval tv_start, tv_end;
  bool timedout = false;
  int badcounter = 0;
  int ioffset;

  if (!p)
    return false;
  if (timeout < 0)
    timeout = 0;
  if ((*datalink = pcap_datalink(p)) < 0)
    return false;
  ioffset = read_util_datalinkoffset(*datalink);
  if (ioffset < 0)
    return false;
  *offset = (u32)ioffset;
  if (timeout > 0)
    gettimeofday(&tv_start, NULL);

  do {
    *pkt = NULL;
    int pcap_status = 0;
    
    if (pcap_selectable_fd_valid == 0) {
      int rc, nonblock;
      nonblock = pcap_getnonblock(p, NULL);
      assert(nonblock == 0);
      rc = pcap_setnonblock(p, 1, NULL);
      assert(rc == 0);
      pcap_status = pcap_next_ex(p, head, pkt);
      rc = pcap_setnonblock(p, nonblock, NULL);
      assert(rc == 0);
    }
    
    if (pcap_status == PCAP_ERROR)
      return false;
    
    if (pcap_status == 0 || *pkt == NULL) {
      if (read_util_pcapselect(p, timeout) == 0)
	timedout = true;
      else
	pcap_status = pcap_next_ex(p, head, (const u8**)pkt);
    }
    
    if (pcap_status == PCAP_ERROR)
      return false;
    
    if (pcap_status == 1 && *pkt != NULL && accept_callback(*pkt, *head, *datalink, *offset))
      break;
    else if (pcap_status == 0 || *pkt == NULL) {
      if (timeout == 0)
	timedout = true;
      else if (timeout > 0) {
	gettimeofday(&tv_end, NULL);
	if (TIMEVAL_SUBTRACT(tv_end, tv_start) >= timeout)
	  timedout = true;
      }
    }
    else
      if (badcounter++ > 50)
	timedout = true;
  } while (!timedout);

  if (timedout)
    return false;
  
  if (rtt) {
    gettimeofday(&tv_end, NULL);
    *rtt = (double)(TIMEVAL_SUBTRACT(tv_end, tv_start)) / 1000.0;
  }
  
  return true;
}

