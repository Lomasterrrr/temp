/*
 *          NESCA4
 *   Сделано от души 2024.
 * Copyright (c) [2024] [lomaster]
 * SPDX-License-Identifier: BSD-3-Clause
 *
*/

#include "../include/nescaengine.h"

static std::mutex stopsend;

NESCARAWSEND::NESCARAWSEND(void)
{
  oklast = false;
  trace = -1;
  total = 0;
  ok = 0;
  er = 0;
  currentfd = 0;
  changefd = 0;
  totalfd = 0;
  maxrate = 0;
  memset(&start, 0, sizeof(start));
  memset(&end, 0, sizeof(start));  
  fds.clear();
  gettimeofday(&start, NULL);
}

NESCARAWSEND::~NESCARAWSEND(void)
{
  for (auto fd : fds)
    if (fd != -1)
      close(fd);
}

void NESCARAWSEND::NRS_loop(std::vector<NESCARAWPACKET_SEND> *pkts)
{
  std::vector<std::future<void>> futures;
  size_t threads, i;

  threads = pkts->size();
  futures.clear();
  i = 0;
  
  thread_pool pool(threads);
  for (; i < pkts->size(); i++) {
    futures.emplace_back(pool.enqueue(std::bind(&NESCARAWSEND::sendpkt, this, &(*pkts)[i])));
    if (futures.size() >= static_cast<size_t>(threads)) {
      for (auto& future : futures)
        future.get();
      futures.clear();
    }
  }
  for (auto& future : futures)
    future.get();
}

void NESCARAWSEND::NRS_next(NESCARAWPACKET_SEND *pkt) {
  sendpkt(pkt);
}

void NESCARAWSEND::NRS_nextfd(size_t num) {
  this->changefd = num;
}

void NESCARAWSEND::NRS_trace(int level) {
  this->trace = level;
}

void NESCARAWSEND::NRS_maxrate(size_t num) {
  this->maxrate = num;
}

void NESCARAWSEND::NRS_fdnum(size_t num)
{
  this->totalfd = num;
  initfds();
}

double NESCARAWSEND::NRS_getsendms(void)
{
  double res;
  res = -1;
  gettimeofday(&end, NULL);
  res = (TIMEVAL_SUBTRACT(end, start)) / 1000;
  return res;
}

void NESCARAWSEND::sendpkt(NESCARAWPACKET_SEND *p)
{
  struct timespec s, e;
  int res = -1;

  if (maxrate > 0) {
    stopsend.lock();
    auto now = std::chrono::high_resolution_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(now - lastsendtime).count();
    auto interval = 1000000000 / maxrate;
    if ((size_t)elapsed < interval)
      std::this_thread::sleep_for(std::chrono::nanoseconds(interval - elapsed));
    lastsendtime = std::chrono::high_resolution_clock::now();
    stopsend.unlock();
  }

  stopsend.lock();
  total++;
  if ((total % changefd) == (changefd -1)) {
    currentfd++;
    if (currentfd >= fds.size())
      currentfd = 0;
  }
  stopsend.unlock();

  clock_gettime(CLOCK_MONOTONIC, &s);
  res = ip_send(NULL, fds.at(currentfd), &p->dst, p->mtu, p->pkt, p->pktlen);
  clock_gettime(CLOCK_MONOTONIC, &e);
  if (res == -1) {
    stopsend.lock();
    er++;
    oklast = false;
    stopsend.unlock();
  }
  else {
    stopsend.lock();
    ok++;
    oklast = true;
    stopsend.unlock();
    if (trace != -1) {
      stopsend.lock();
      std::cout << "SENT (" << GETELAPSED(s,e) << " ns) " << read_ippktinfo(p->pkt, p->pktlen, trace) << std::endl;
      stopsend.unlock();
    }
  }
}

void NESCARAWSEND::initfds(void)
{
  size_t i;
  int fd;

  fd = -1;
  i = 1;
  
  for (; i <= totalfd; i++, fd = -1) {
    fd = nescasocket;
    if (fd != -1)
      fds.push_back(fd);
  }
}

void NESCARAWSEND::NRS_stats(void)
{
  printf("Packet send statistics - \n");
  printf("Total sent: %ld\n", total);
  printf("Successfully sent: %ld\n", ok);
  printf("Unsuccessfully sent: %ld\n", er);
  printf("Last sent: %s\n",
	 (oklast ? "successfully" : "unsuccessfully"));
}
