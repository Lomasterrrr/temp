/*
 *          NESCA4
 *   Сделано от души 2024.
 * Copyright (c) [2024] [lomaster]
 * SPDX-License-Identifier: BSD-3-Clause
 *
*/

#include "../include/nescaengine.h"

static std::mutex stoprecv;

NESCARAWRECV::NESCARAWRECV(void)
{
  queue.clear();
  maxpktlen = 0;
  totalpcaps = 0;
  activepcaps = 0;
  trace = -1;
  ok = er = total = 0;
  oklast = false;
}

static void* close_pcap(void* arg)
{
  pcap_t* handle = (pcap_t*)arg;
  pcap_close(handle);
  return NULL;
}

static void close_pcap_async(pcap_t* handle)
{
  pthread_t thread;
  pthread_create(&thread, NULL, close_pcap, handle);
  pthread_detach(thread);
}

void NESCARAWRECV::NRR_free(void)
{
  if (queue.empty())
    return;
  if (freequeue == queue.end() || std::next(freequeue) == queue.end())
    freequeue = queue.begin();
  else
    freequeue++;
  if (freequeue->first)
    close_pcap_async(freequeue->first);
}

void NESCARAWRECV::NRR_loopfree(size_t num)
{
  size_t i;
  if (num == 0)
    num = activepcaps;
  for (i = 1;i<=num;i++)
    NRR_free();
}

void NESCARAWRECV::NRR_loop(void)
{
  std::vector<std::future<void>> futures;
  size_t threads, i;

  threads = activepcaps;
  futures.clear();
  i = 1;

  thread_pool pool(threads);
  for (; i <= threads; i++) {
    futures.emplace_back(pool.enqueue(std::bind(&NESCARAWRECV::NRR_next, this)));
    if (futures.size() >= static_cast<size_t>(threads)) {
      for (auto& future : futures)
        future.get();
      futures.clear();
    }
  }
  for (auto& future : futures)
    future.get();
}

void NESCARAWRECV::NRR_next(void)
{
  NESCARAWPACKET_RECV *ptr = NULL;
  const u8 *data = NULL;

  stoprecv.lock();
  if (queue.empty())
    return;
  if (currentqueue == queue.end() || std::next(currentqueue) == queue.end())
    currentqueue = queue.begin();
  else
    currentqueue++;
  total++;
  stoprecv.unlock();

  ptr = currentqueue->second;
  data = ncpcap_ipread(currentqueue->first, &ptr->pktlen, ptr->ns, &ptr->end, &ptr->nfo, true);
  if (ptr->pktlen <= maxpktlen && data) {
    stoprecv.lock();
    ptr->rtt = (TIMEVAL_SUBTRACT(ptr->end, ptr->start) / 1000);
    memcpy(ptr->pkt, data, ptr->pktlen);
    ok++;
    oklast = true;
    pcap_breakloop(currentqueue->first);
    stoprecv.unlock();
    if (trace != -1) {
      stoprecv.lock();
      std::cout << "RCVD (" << ptr->rtt << " ms) " << read_ippktinfo(ptr->pkt, (ptr->pktlen + ptr->nfo.headerlen), trace) << std::endl;
      stoprecv.unlock();
    }
  }
  else {
    oklast = false;
    stoprecv.lock();
    er++;
    stoprecv.unlock();
  }
}

void NESCARAWRECV::NRR_buflen(size_t num) {
  this->maxpktlen = num;
}

bool NESCARAWRECV::initpkt(NESCARAWPACKET_RECV **p)
{
  stoprecv.lock();
  (*p)->pkt = (u8*)calloc(maxpktlen, sizeof(u8));
  stoprecv.unlock();
  if (!(*p)->pkt)
    return false;
  (*p)->pktlen = 0;
  return true;
}

void NESCARAWRECV::NRR_queue(const std::string& device, const std::string &bpf, int snaplen, int promisc, NESCARAWPACKET_RECV *p)
{
  pcap_t *pp;
  
  stoprecv.lock();
  totalpcaps++;
  stoprecv.unlock();

  if (!initpkt(&p))
    return;
  
  pp = NULL;
  stoprecv.lock();
  gettimeofday(&p->start, NULL);
  stoprecv.unlock();
  pp = ncpcap_openlive(device.c_str(), snaplen, promisc, to_ns(1));
  if (p) {
    if ((pcap_set_immediate_mode(pp, 1)) != -1) {
      pcap_set_buffer_size(pp, 1024*1024);
      pcap_set_rfmon(pp, 1);
      stoprecv.lock();
      activepcaps++;
      stoprecv.unlock();
      ncpcap_filter(pp, bpf.c_str());
      stoprecv.lock();
      queue[pp] = p;
      stoprecv.unlock();
    }
  }
}

void NESCARAWRECV::NRR_trace(int level) {
  this->trace = level;
}

void NESCARAWRECV::NRR_queueloop(const std::string &device, const std::string &src, int snaplen,
				 int promisc, std::vector<NESCARAWPACKET_RECV> *pkts)
{
  std::vector<std::future<void>> futures;
  size_t threads;
  std::string bpf;

  threads = pkts->size()+1;
  futures.clear();

  thread_pool pool(threads);
  for (auto& p : *pkts) {
    bpf = p.proto + " and " + " src host " + p.dst + " and dst host " + src;
    if (p.port > 0)
      bpf += " and port " + std::to_string(p.port);
    futures.emplace_back(pool.enqueue(std::bind(&NESCARAWRECV::NRR_queue, this, device, bpf, snaplen, promisc, &p)));
    if (futures.size() >= static_cast<size_t>(threads)) {
      for (auto& future : futures)
        future.get();
      futures.clear();
    }
  }
  for (auto& future : futures)
    future.get();
}

void NESCARAWRECV::NRR_stats(void)
{
  printf("Packet read statistics - \n");
  printf("Total read: %ld\n", total);
  printf("Successfully read: %ld\n", ok);
  printf("Unsuccessfully read: %ld\n", er);
  printf("Last read: %s\n",
	 (oklast ? "successfully" : "unsuccessfully"));
  printf("Active pcaps: %ld\n", activepcaps);
  printf("Total pcaps: %ld\n", totalpcaps);  
}

