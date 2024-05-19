/*
 *          NESCA4
 *   Сделано от души 2024.
 * Copyright (c) [2024] [lomaster]
 * SPDX-License-Identifier: BSD-3-Clause
*/

#include <arpa/inet.h>
#include <cstdio>
#include <string>
#include <sys/types.h>
#include <vector>
#include <algorithm>
#include <arpa/inet.h>

#include "../include/nescaopts.h"
#include "../include/nescalog.h"
#include "../include/nescaengine.h"
#include "../include/nescadata.h"

#define NESCA4VERSION "20240512"

NESCADATA2 n;
NESCAOPTS no;

template <typename Func, typename... Args>
void nesca_group_execute(size_t threads, std::vector<NESCATARGET *> group,
                         Func &&func, Args &&...args);
void NESCASCAN(std::vector<NESCATARGET *> ips);
void PRINTNESCA(std::vector<NESCATARGET *> ips);
void PRENESCASCA(void);

int main(int argc, char **argv)
{
  if (!checkroot())
    nescaerrlog("UNIX requires root permissions, to use raw sockets (use: sudo "
		+ std::string(argv[0]) + ")");
  no.args_init();
  no.config_parse(DEFAULT_CFG);
  no.args_parse(argc, argv);
  if (no.check_configpath())
    no.config_parse(no.get_configpath());
  if (no.check_printargs())
    no.args_print();
  no.args_proc();
  
  nescalogpath = no.get_txtsave();
  nescarunlog(NESCA4VERSION);

  n.nescadatainit();
  if (optind < argc)
    n.set_runtargets(splitstring(argv[optind], ','));
  if (no.check_randomip())
    n.set_randomip4s(no.get_randomip());
  if (no.check_import())
    n.set_importfile(no.get_import());
  if (n.targetsgetnum() > 1000 && !no.check_verbose(1) && !no.check_verbose(2) && !no.check_verbose(3))
    nescalog(nescalogpath, "If you need to see the progress of the scan you can use -vv\n");

  if (!no.check_noping())
    PRENESCASCA();
  else
    NESCASCAN({});
  
  if (no.check_noscan())
    nescalog(nescalogpath, "\n");
  nescaendlog(n.goodnumget());
  return 0;
}

void PRENESCASCA(void)
{
  std::vector<NESCATARGET*> ips;
  size_t i, total, grouplen, group;

  total = n.targetsgetnum();
  group = no.get_pingming();
  i = 0;
  
  while (i < total) {
    grouplen = std::min<size_t>(group, total - i);
    grouplen = std::min<size_t>(grouplen, no.get_pingmaxg());

    n.targetsinit(grouplen);
    ips = n.targetsget(grouplen);

    if (no.get_verbose() > 0)
      nescalog(nescalogpath, "%s Running ping scan for %lld targets\n", get_time(), grouplen);
    nesca_group_execute(grouplen, ips, NESCAPING_thread, &no);

    ips.erase(std::remove_if(ips.begin(), ips.end(), [](NESCATARGET* target) { return !target->good; }), ips.end());
    std::sort(ips.begin(), ips.end(), [](NESCATARGET* a, NESCATARGET* b) {
      return a->rtt < b->rtt;
    });

    NESCASCAN(ips);
    i += grouplen;
    group += no.get_groupplus();
  }
}

void NESCASCAN(std::vector<NESCATARGET*> ips)
{
  size_t i, total, grouplen, group;
  bool noping = false;

  if (ips.empty())
    noping = true;
  if (noping)
    total = n.targetsgetnum();
  else
    total = ips.size();
  group = no.get_scanming();
  i = 0;

  while (i < total) {
    grouplen = std::min<size_t>(group, total - i);
    grouplen = std::min<size_t>(grouplen, no.get_scanmaxg());
    
    if (noping) {
      n.targetsinit(grouplen);
      ips = n.targetsget(grouplen);
    }
    if (no.get_verbose() > 0 && no.get_verbose() < 2)
      nescalog(nescalogpath, "%s Running scan for %lld targets\n", get_time(), grouplen);
    if (no.get_verbose() > 1)
      nescalog(nescalogpath, "%s Running host resolution for %lld targets\n", get_time(), grouplen);
    if (!no.check_noresolv())
      nesca_group_execute(grouplen, ips, NESCARSLV_thread, &no);
     if (no.get_verbose() > 1)
      nescalog(nescalogpath, "%s Running port scan for %lld targets\n", get_time(), grouplen);
    if (!no.check_noscan())
      nesca_group_execute(grouplen, ips, NESCASCAN_thread, &no);
    if (no.get_verbose() > 1)
      nescalog(nescalogpath, "%s Running http probe for %lld targets\n", get_time(), grouplen);
    if (!no.check_noproc() && !no.check_noscan())
      nesca_group_execute(grouplen, ips, NESCAHTTP_thread, &no);
    if (no.get_verbose() > 1)
      nescalog(nescalogpath, "%s Running processing for %lld targets\n", get_time(), grouplen);
    if (!no.check_noproc() && !no.check_noscan())
      nesca_group_execute(grouplen, ips, NESCAPROC_thread, &no);

    PRINTNESCA(ips);

    i += grouplen;
    group += no.get_scangroupplus();
  }
}

void PRINTNESCA(std::vector<NESCATARGET *> ips)
{
  for (const auto& t : ips) {
    if (no.check_noscan())
      nescahdrlog(t->ip, t->newdns, t->rtt);
    else {
      if (t->checkopenports() || no.check_failed()) {
	nescahdrlog(t->ip, t->newdns, t->rtt);
	if (!no.check_noscan())
	  nescalog(nescalogpath, "\n");
	nescacontentlog("ports", portblock(t, &no));
	if (!t->idents.empty())
	  nescacontentlog("identifier", enclose(identblock(t, &no)));
	if (!t->databaseres.empty())
	  nescacontentlog("database", enclose(join(t->databaseres, "; ")));
	if (!t->login.empty() && !t->pass.empty())
	  nescacontentlog("passwd", passblock(t->login, t->pass));
	if (!t->redirect.empty())
  	  nescacontentlog("redirect", enclose(t->redirect));
	if (!t->html.empty() && no.check_displayhtml())
	  for (const auto &h : t->html)
	    nescacontentlog("html", enclose(h));
	nescalog(nescalogpath, "\n");
      }
    }
  }
}

template <typename Func, typename... Args>
void nesca_group_execute(size_t threads, std::vector<NESCATARGET *> group,
                         Func &&func, Args &&...args)
{
  std::vector<std::future<void>> futures;
  thread_pool pool(threads);

  for (auto& t : group) {
    futures.emplace_back(pool.enqueue(std::forward<Func>(func), t, std::forward<Args>(args)...));
    if (futures.size() >= static_cast<size_t>(threads)) {
      for (auto& future : futures)
        future.get();
      futures.clear();
    }
  }
  for (auto& future : futures)
    future.get();
}
