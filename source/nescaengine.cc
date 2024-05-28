#include "../include/nescaengine.h"
#include "../include/nescalog.h"
#include "../ncsock/include/ncpcap.h"
#include <arpa/inet.h>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <ios>
#include <mutex>
#include <netinet/in.h>
#include <ostream>
#include <pcap/pcap.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>
#include <iostream>

static u16 ackporti = 0;
static u16 synporti = 0;
static u16 initporti = 0;
static u16 udpporti = 0;

std::mutex stop;

void NESCARSLV_thread(NESCATARGET *t, NESCAOPTS *no)
{
  char dnsbuf[1024];
  if (no->check_resolvsrcport())
    no->set_resolvsrcport(random_srcport());

  nanodelay(no->get_resolvdelay());
  dns_util_getip4(t->ip.c_str(), no->get_resolvsrcport(), no->get_resolvtimeout(), dnsbuf, 1024);

  stop.lock();
  t->newdns = dnsbuf;
  stop.unlock();
}

void NESCAHTTP_thread(NESCATARGET *t, NESCAOPTS *no)
{
  nescadelay_t timeout = 0, replytimeout = 0;
  std::vector<u16> ports;
  struct http_request r;
  
  for (const auto& p : no->get_httpports())
    if (t->checkport(p, PORT_OPEN, IPPROTO_TCP))
      ports.push_back(p);
  if (ports.empty())
    return;

  timeout = no->get_httptimeout();
  replytimeout = no->get_httpreplytimeout();
  
  for (const auto& p : ports) {
    http_init_req(&r, "GET", "", "", 0, "/", 0, 0);
    if (no->check_httpheader())
      no->get_httpheader(&r);
    send_http(&r, t, t->ip, p, timeout, replytimeout, no);
    
    stop.lock();
    http_free_req(&r);
    stop.unlock();
  }
}

void NESCAPROC_thread(NESCATARGET *t, NESCAOPTS *no)
{
  if (t->checkports(no->get_httpports(), PORT_OPEN, IPPROTO_TCP))
    httpprc(t, no);
  if (t->checkport(21, PORT_OPEN, IPPROTO_TCP))
    ftpprc(t, no);
}

void httpprc(NESCATARGET *t, NESCAOPTS *no)
{
  char title[RECV_BUFFER_SIZE];
  struct prcblock prc;
  
  if (!t->html.empty()) {
    for (auto& h : t->html) {
      http_qprc_title(h.c_str(), title, RECV_BUFFER_SIZE);
      if (std::string(title) != "n/a" && !std::string(title).empty())
	t->addid(HTTP_SERVICE, title);
    }
  }
  
  if (!no->check_nodbcheck()){
    for (const auto& i : t->getids(HTTP_SERVICE)) {
      prc = no->procprobe(i, FIND_TITLE);
      if (prc.check)
	t->databaseres.push_back(prc.keyword);
    }
    prc.check = false;
    for (auto& h : t->html) {
      prc = no->procprobe(h, FIND_HTML);
      if (prc.check)
	t->databaseres.push_back(prc.keyword);
    }
    prc.check = false;  
    prc = no->procprobe(t->redirect, FIND_REDIRECT);
    if (prc.check)
      t->databaseres.push_back(prc.keyword);
  }
}

void ftpprc(NESCATARGET *t, NESCAOPTS *no)
{
  u8 version[2048];
  ftp_qprc_version(t->ip.c_str(), 21, 1e+9, version, sizeof(version));
  if (!std::string((char*)version).empty())
    t->addid(FTP_SERVICE, (char*)version);
}

u8 *tcp4probe(NESCAOPTS *no, const u32 dst, u16 dstport, u8 type, u32 *pktlen)
{
  u8 tcpflags = 0, *res = NULL, ttl = 0;
  bool df = false;
  u16 srcport = 0;
  
  switch (type) {
  case TCP_PING_ACK:
    tcpflags = TCP_FLAG_ACK;
    dstport = no->get_ackports()[ackporti++];
    break;
  case TCP_PING_SYN:
    tcpflags = TCP_FLAG_SYN;
    dstport = no->get_synports()[synporti++];
    break;
  case 0:
    tcpflags = no->get_scanflags();
    break;
  default:
    tcpflags = no->get_tcpflags(type);
    break;
  }
  
  if (no->check_srcport())
    srcport = no->get_srcport();
  else
    srcport = random_srcport();
  if (no->check_ttl())
    ttl = no->get_ttl();
  else
    ttl = random_num_u32(54, 203);
  if (!no->check_mtu())
    df = true;

  res = tcp4_build_pkt(no->get_src(), dst, ttl, random_u16(), 0, df,
       no->get_ipopt(), no->get_ipoptlen(), srcport, dstport, random_u32(),
       0, 0, tcpflags, no->get_window(), 0, NULL, 0, no->get_payload().c_str(),
       no->get_payloadlen(), pktlen, no->check_badsum());

  return res;
}

u8 *icmp4probe(NESCAOPTS *no, const u32 dst, u8 type, u32 *pktlen)
{
  u8 icmptype = 0, *res = NULL, ttl = 0;
  bool df = false;

  switch (type) {
  case ICMP_PING_ECHO:
    icmptype = ICMP4_ECHO;
    break;
  case ICMP_PING_INFO:
    icmptype = ICMP4_INFO_REQUEST;
    break;
  case ICMP_PING_TIME:
    icmptype = ICMP4_TIMESTAMP;
    break;
  }
  
  if (no->check_ttl())
    ttl = no->get_ttl();
  else
    ttl = random_num_u32(54, 203);
  if (!no->check_mtu())
    df = true;

  res = icmp4_build_pkt(no->get_src(), dst, ttl, random_u16(), 0, df,
        no->get_ipopt(), no->get_ipoptlen(), random_u16(), random_u16(),
        icmptype, 0, no->get_payload().c_str(), no->get_payloadlen(), pktlen,
        no->check_badsum());

  return res;
}

u8 *sctp4probe(NESCAOPTS *no, const u32 dst, u16 dstport, u8 type, u32 *pktlen)
{
  u8 *res = NULL, ttl = 0;
  bool df = false;
  char *chunk = NULL;
  int chunklen = 0;
  u32 vtag = 0;
  u16 srcport = 0;

  switch (type) {
  case SCTP_INIT_PING:
    dstport = no->get_initports()[initporti++];
  case SCTP_INIT_SCAN:
    chunklen = sizeof(struct sctp_chunk_hdr_init);
    chunk = (char*)malloc(chunklen);
    sctp_pack_chunkhdr_init(chunk, SCTP_INIT, 0, chunklen, random_u32(), 32768, 10, 2048, random_u32());
    break;
  case SCTP_COOKIE_SCAN:
    chunklen = sizeof(struct sctp_chunk_header_cookie_echo) + 4;
    chunk = (char*)malloc(chunklen);
    *((u32*)((char*)chunk + sizeof(struct sctp_chunk_header_cookie_echo))) = random_u32();
    sctp_pack_chunkhdr_cookie_echo(chunk, SCTP_COOKIE_ECHO, 0, chunklen);
    vtag = random_u32();
    break;
  }
  
  if (no->check_srcport())
    srcport = no->get_srcport();
  else
    srcport = random_srcport();
  if (no->check_ttl())
    ttl = no->get_ttl();
  else
    ttl = random_num_u32(54, 203);
  if (!no->check_mtu())
    df = true;

  res = sctp4_build_pkt(no->get_src(), dst, ttl,
        random_u16(), 0, df, no->get_ipopt(), no->get_ipoptlen(), srcport, dstport, vtag, chunk,
        chunklen, no->get_payload().c_str(), no->get_payloadlen(), pktlen, no->check_adler32(), no->check_badsum());

  if (chunk)
    free(chunk);
  
  return res;
}

u8 *udp4probe(NESCAOPTS *no, const u32 dst, u16 dstport, u8 type, u32 *pktlen)
{
  u8 *res = NULL, ttl = 0;
  bool df = false;
  u16 srcport = 0;

  if (type == UDP_PING)
    dstport = no->get_udpports()[udpporti++];

  if (no->check_srcport())
    srcport = no->get_srcport();
  else
    srcport = random_srcport();
  if (no->check_ttl())
    ttl = no->get_ttl();
  else
    ttl = random_num_u32(54, 203);
  if (!no->check_mtu())
    df = true;

  res = udp4_build_pkt(no->get_src(), dst, ttl, random_u16(), 0, df, no->get_ipopt(), no->get_ipoptlen(),
        srcport, dstport, no->get_payload().c_str(), no->get_payloadlen(), pktlen, no->check_badsum());

  return res;
}

int readscan(u8 *pkt, u32 pktlen, int type)
{
  const u8 *res = NULL;
  struct abstract_iphdr ip;

  res = (u8*)read_util_ip4getdata_any(pkt, &pktlen, &ip);
  if (!res || !pkt)
    return -88;
    
  if (type == SCTP_INIT_SCAN || type == SCTP_COOKIE_SCAN || type == SCTP_INIT_PING) {
    const struct sctp_hdr *sctp = (struct sctp_hdr*)res;
    const struct sctp_chunk_hdr *chunk = (struct sctp_chunk_hdr*)((u8*)sctp + 12);

    if (type == SCTP_INIT_SCAN) {
      if (chunk->type == SCTP_INIT_ACK)
        return PORT_OPEN;
      else if (chunk->type == SCTP_ABORT)
        return PORT_CLOSED;
    }
    if (type == SCTP_COOKIE_SCAN)
      if (chunk->type == SCTP_ABORT)
        return PORT_CLOSED;
  }
  else if (type == UDP_SCAN) {
    if (ip.proto == IPPROTO_ICMP) {
      const struct icmp4_hdr *icmp = (struct icmp4_hdr*)res;
      if (icmp->type == 3 && icmp->code == 3)
        return PORT_CLOSED;
    }
    else if (ip.proto == IPPROTO_UDP) /* its real? */
      return PORT_OPEN;
    else
      return PORT_FILTER;
  }
  else {
    const struct tcp_hdr *tcp = (struct tcp_hdr*)res;
    switch (type) {
      case TCP_MAIMON_SCAN: {
        if (tcp->th_flags == TCP_FLAG_RST)
          return PORT_CLOSED;
        return PORT_OPEN_OR_FILTER;
      }
      case TCP_PSH_SCAN:
      case TCP_FIN_SCAN:
      case TCP_XMAS_SCAN:
      case TCP_NULL_SCAN: {
        if (tcp->th_flags == TCP_FLAG_RST)
          return PORT_CLOSED;
        return PORT_OPEN;
      }
      case TCP_WINDOW_SCAN: {
        if (tcp->th_flags == TCP_FLAG_RST) {
          if (tcp->th_win > 0)
            return PORT_OPEN;
          else
            return PORT_CLOSED;
          return PORT_FILTER;
        }
      }
      case TCP_ACK_SCAN: {
        if (tcp->th_flags == TCP_FLAG_RST)
          return PORT_NO_FILTER;
        return PORT_FILTER;
      }
      default: {
        switch (tcp->th_flags) {
          case 0x12:
            return PORT_OPEN;
          case 0x1A:
            return PORT_OPEN;
          case TCP_FLAG_RST:
            return PORT_CLOSED;
          default:
            return PORT_FILTER;
        }
      }
    }
  }

  return PORT_ERROR;
}

bool readping(u8 *pkt, u32 pktlen, int type)
{
  struct abstract_iphdr ip;
  u8 *res = NULL;
  u8 icmptype = 0;
  u8 tcpflags = 0;

  res = (u8*)read_util_ip4getdata_any(pkt, &pktlen, &ip);
  if (!res)
    return false;

  if (type == ICMP_PING_ECHO || type == ICMP_PING_TIME || type == ICMP_PING_INFO) {
    const struct icmp4_hdr *icmp;
    icmp = (struct icmp4_hdr*)res;
    
    icmptype = icmp->type;
    if (type == ICMP_PING_TIME && icmptype == ICMP4_TIMESTAMPREPLY)
      return true;
    if (type == ICMP_PING_ECHO && icmptype == ICMP4_ECHOREPLY)
      return true;
    if (type == ICMP_PING_INFO && icmptype == ICMP4_INFO_REPLY)
      return true;
  }
  if (type == TCP_PING_ACK || type == TCP_PING_SYN) {
    const struct tcp_hdr *tcp;
    tcp = (struct tcp_hdr*)res;

    tcpflags = tcp->th_flags;
    if (type == TCP_PING_ACK && tcpflags == TCP_FLAG_RST)
      return true;
    if (type == TCP_PING_SYN && tcpflags)
      return true;
  }
  if (type == SCTP_INIT_PING) {
    const struct sctp_hdr *sctp;
    sctp = (struct sctp_hdr*)res;
    
    if (sctp->srcport)
      return true;
  }
  if (type == UDP_PING) {
    if (ip.proto == IPPROTO_ICMP) {
      const struct icmp4_hdr *icmp;
      icmp = (struct icmp4_hdr*)res;
      if (icmp->type == 3 && icmp->code == 3)
        return true;
    }
    if (ip.proto == IPPROTO_UDP)
      return true;
  }
  
  return false;
}

std::string get_protocol(int type)
{
  switch (type) {
  case ICMP_PING_ECHO:
  case ICMP_PING_INFO:
  case ICMP_PING_TIME:
    return "icmp";
  case TCP_PING_SYN:
  case TCP_PING_ACK:
  case TCP_SYN_SCAN:
  case TCP_XMAS_SCAN:
  case TCP_FIN_SCAN:
  case TCP_NULL_SCAN:
  case TCP_ACK_SCAN:
  case TCP_WINDOW_SCAN:
  case TCP_MAIMON_SCAN:
  case TCP_PSH_SCAN:
    return "tcp";
  case SCTP_INIT_SCAN:
  case SCTP_COOKIE_SCAN:
  case SCTP_INIT_PING:
    return "sctp";
  case UDP_PING:
  case UDP_SCAN:
    return "udp";
  case ARP_PING:
    return "arp";
  default:
    return "???";
  }
}

NESCARAWENGINE::NESCARAWENGINE(std::vector<NESCATARGET*> targets, NESCAOPTS *no, NESCADATA2 *nd, u8 worktype)
{
  std::vector<int> types;
  NESCARAWSEND send;
  NESCARAWRECV recv;

  this->onsend.clear();
  this->forrecv.clear();
  this->no = NULL;
  this->nd = NULL;
  this->fixrtt = 0;
  this->worktype = 0;

  this->no = no;
  this->nd = nd;
  this->worktype = worktype;
  
  types = get_types();
  send.NRS_trace(no->get_pkttrace());
  recv.NRR_trace(no->get_pkttrace());
  recv.NRR_buflen(1024);
  send.NRS_fdnum(100);
  send.NRS_maxrate(0);
  send.NRS_nextfd(10);

  for (const auto& t : types) {
    build_pktloop_type(targets, t);
    
    recv.NRR_queueloop(no->get_device(), no->get_strsrc(), 512, 0, &forrecv);
    send.NRS_loop(&onsend);
    fixrtt = send.NRS_getsendms();
    recv.NRR_loop();
    
    read_pkts();
    free_pkts();
    recv.NRR_loopfree(0);
  }
}

void NESCARAWENGINE::read_pkts(void)
{
  int portstate, proto;
  NESCATARGET *t;
  
  t = NULL;
  portstate = -1;
  proto = 0;
  
  for (auto & p : forrecv) {
    t = nd->targetgetip4(p.dst);
    if (worktype == 0) {
      if (t->good)
	continue;
      if ((readping(p.pkt, p.pktlen, p.type))) {
	t->rtt = (p.rtt - fixrtt);
	t->good = true;
      }
      else {
	t->rtt = 0;
	t->good = false;	
      }
    }
    if (worktype == 1) {
      portstate = readscan(p.pkt, p.pktlen, p.type);
      if (p.proto == "tcp")
	proto = IPPROTO_TCP;
      else if (p.proto == "sctp")
	proto = IPPROTO_SCTP;
      else if (p.proto == "udp")
	proto = IPPROTO_UDP;

      if (portstate == -88) {
	if (p.type != TCP_SYN_SCAN && p.type != TCP_ACK_SCAN &&
	    p.type != TCP_WINDOW_SCAN)
	  t->addport(p.port, PORT_OPEN_OR_FILTER, proto, p.type);
	else
	  t->addport(p.port, PORT_FILTER, proto, p.type);
      }
      else
	t->addport(p.port, portstate, proto, p.type);
    }
  }
}

void NESCARAWENGINE::free_pkts(void)
{
  for (auto & p : onsend)
    if (p.pkt)
      free(p.pkt);
  for (auto & p : forrecv)
    if (p.pkt)
      free(p.pkt);
  onsend.clear();
  forrecv.clear();
}

NESCARAWENGINE::~NESCARAWENGINE(void)
{
  free_pkts();
}

std::vector<int> NESCARAWENGINE::get_types(void)
{
  std::vector<int> res;

  if (worktype == 0) {
    if (no->check_echoping())
      res.push_back(ICMP_PING_ECHO);
    if (no->check_infoping())
      res.push_back(ICMP_PING_INFO);
    if (no->check_timeping())
      res.push_back(ICMP_PING_TIME);
    if (no->check_synping())
      res.push_back(TCP_PING_SYN);
    if (no->check_ackping())
      res.push_back(TCP_PING_ACK);
    if (no->check_udpping())
      res.push_back(UDP_PING);
    if (no->check_initping())
      res.push_back(SCTP_INIT_PING);
  }
  else if (worktype == 1) {
    if (no->check_synscan())
      res.push_back(TCP_SYN_SCAN);
    if (no->check_xmasscan())
      res.push_back(TCP_XMAS_SCAN);
    if (no->check_maimonscan())
      res.push_back(TCP_MAIMON_SCAN);
    if (no->check_ackscan())
      res.push_back(TCP_ACK_SCAN);
    if (no->check_pshscan())
      res.push_back(TCP_PSH_SCAN);
    if (no->check_finscan())
      res.push_back(TCP_FIN_SCAN);
    if (no->check_windowscan())
      res.push_back(TCP_WINDOW_SCAN);
    if (no->check_nullscan())
      res.push_back(TCP_NULL_SCAN);
    if (no->check_udpscan())
      res.push_back(UDP_SCAN);
    if (no->check_sctpcookiescan())
      res.push_back(SCTP_COOKIE_SCAN);
    if (no->check_sctpinitscan())
      res.push_back(SCTP_INIT_SCAN);
    if (no->check_scanflags())
      res.push_back({0});
  }
  
  return res;
}

void NESCARAWENGINE::build_pktloop_type(std::vector<NESCATARGET*> targets, int type)
{
  for (const auto& t : targets) {
    if (worktype == 1)
      for (const auto port: no->get_ports())
	build_pkt(t, port.port, type);
    else
      build_pkt(t, 0, type);
  }
}

void NESCARAWENGINE::build_pktloop(std::vector<NESCATARGET*> targets)
{
  std::vector<int> types;
  size_t i;

  i = 0;
  types = get_types();

  for (; i < targets.size(); i++)
    for (const auto& type : types)
      build_pktloop_type(targets, type);
}

void NESCARAWENGINE::build_pkt(NESCATARGET *t, u16 dstport, int type)
{
  struct sockaddr_in *addr4;
  NESCARAWPACKET_RECV res1;  
  NESCARAWPACKET_SEND res;
  u32 dst;

  res1.dst = t->ip;
  
  if (worktype == 0)
    res1.ns = no->get_pingtimeout();
  else if (worktype == 1) {
    if (t->rtt > 0 && t->good && no->check_scantimemult())
      res1.ns = no->get_speedscantime(t->rtt);
    else if (no->check_scantimeout())
      res1.ns = no->get_scantimeout();
  }

  dst = inet_addr(t->ip.c_str());
  addr4 = (struct sockaddr_in*)&res.dst;
  addr4->sin_family = AF_INET;
  addr4->sin_addr.s_addr = dst;
  res.mtu = no->get_mtu();
  res1.type = type;
  res1.port = dstport;

  switch(type) {
  case ICMP_PING_ECHO:
  case ICMP_PING_INFO:
  case ICMP_PING_TIME:
    res1.proto = "icmp";
    res.pkt = icmp4probe(no, dst, type, &res.pktlen);
    break;
  case UDP_PING:
  case UDP_SCAN:
    res1.proto = "udp or icmp";
    res.pkt = udp4probe(no, dst, dstport, type, &res.pktlen);
    break;
  case SCTP_COOKIE_SCAN:
  case SCTP_INIT_SCAN:
  case SCTP_INIT_PING:
    res1.proto = "sctp";
    res.pkt = sctp4probe(no, dst, dstport, type, &res.pktlen);
    break;
  default:
    res1.proto = "tcp";
    res.pkt = tcp4probe(no, dst, dstport, type, &res.pktlen);
    break;
  }
  
  onsend.push_back(res);
  forrecv.push_back(res1);
}

/*
void NESCARAWENGINE::build_pkt(NESCATARGET *t, NESCAOPTS *no, u8 type)
{
  struct NESCAPACKET p;

}
*/


/* ....
u8 *arp4probe(NESCAOPTS *no, const u32 dst, u8 type, u32 *pktlen)
{
  u8 *res = NULL;

   ip4_addreth_t daddr, saddr;
   eth_addr_t ethsaddr;
   memcpy(saddr.data, &n->src, sizeof(saddr.data));

   memcpy(daddr.data, &dst, sizeof(daddr.data));
   memcpy(ethsaddr.data, n->srcmac, ETH_ADDR_LEN);

   res = arp4_build_pkt(ethsaddr, MAC_STRING_TO_ADDR(ETH_ADDR_BROADCAST),
ARP_HRD_ETH, ARP_PRO_IP, ETH_ADDR_LEN, IP4_ADDR_LEN, ARP_OP_REQUEST, ethsaddr,
       saddr, MAC_STRING_TO_ADDR("\x00\x00\x00\x00\x00\x00"), daddr, packetlen);
  return res;
}
*/
