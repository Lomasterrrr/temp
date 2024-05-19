#include "../include/nescaengine.h"
#include "../include/nescalog.h"
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <mutex>
#include <netinet/in.h>
#include <unistd.h>
#include <vector>

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

void NESCASCAN_port(const u32 *dst, nescadelay_t timeout, NESCATARGET *t, NESCAPORT &p, NESCAOPTS *no)
{
  int fd, res, portstat = PORT_ERROR;
  std::vector<u8> typesscan;
  double tmptime;
  u8 *pkt;

  /* send probe */
  if (p.proto == IPPROTO_UDP && no->check_udpscan())
    typesscan.push_back(UDP_SCAN);
  else if (p.proto == IPPROTO_SCTP) {
    if (no->check_sctpcookiescan())
      typesscan.push_back(SCTP_COOKIE_SCAN);
    if (no->check_sctpinitscan())
      typesscan.push_back(SCTP_INIT_SCAN);    
  }
  else if (p.proto == IPPROTO_TCP) {
    if (no->check_synscan())
      typesscan.push_back(TCP_SYN_SCAN);
    if (no->check_xmasscan())
      typesscan.push_back(TCP_XMAS_SCAN);
    if (no->check_maimonscan())
      typesscan.push_back(TCP_MAIMON_SCAN);
    if (no->check_ackscan())
      typesscan.push_back(TCP_ACK_SCAN);
    if (no->check_pshscan())
      typesscan.push_back(TCP_PSH_SCAN);
    if (no->check_finscan())
      typesscan.push_back(TCP_FIN_SCAN);
    if (no->check_windowscan())
      typesscan.push_back(TCP_WINDOW_SCAN);
    if (no->check_nullscan())
      typesscan.push_back(TCP_NULL_SCAN);
    if (no->check_scanflags())
      typesscan.push_back({0});
  }

  for (const auto &typescan : typesscan) {
    fd = nescasocket;
    if (!fd)
      continue;
    res = sendprobe(fd, no, *dst, p.port, typescan);
    stop.lock();
    close(fd);
    stop.unlock();
    if (res == -1) {
      stop.lock();
      t->addport(p.port, PORT_ERROR, p.proto, typescan);
      stop.unlock();
      continue;
    }
    
    /* recv response */
    pkt = recvpacket(*dst, typescan, timeout, &tmptime, no);
    if (!pkt) {
      stop.lock();
      free(pkt);
      stop.unlock();
      if (typescan != TCP_SYN_SCAN && typescan != TCP_ACK_SCAN &&
	  typescan != TCP_WINDOW_SCAN) {
	stop.lock();
	t->addport(p.port, PORT_OPEN_OR_FILTER, p.proto, typescan);
	stop.unlock();
      }
      else {
	stop.lock();
	t->addport(p.port, PORT_FILTER, p.proto, typescan);
	stop.unlock();
      }
      continue;
    }
    
    /* read packet */
    stop.lock();
    portstat = readscan(*dst, pkt, typescan);
    free(pkt);
    t->addport(p.port, portstat, p.proto, typescan);
    stop.unlock();
  }
}

void NESCASCAN_thread(NESCATARGET *t, NESCAOPTS *no)
{
  std::vector<std::future<void>> futures;
  nescadelay_t timeout = 0, delay;
  struct sockaddr_in ip4;
  size_t threads;

  ip4.sin_family = AF_INET;
  ip4.sin_addr.s_addr = inet_addr(t->ip.c_str());

  if (t->rtt > 0 && t->good && no->check_scantimemult())
    timeout = no->get_speedscantime(t->rtt);
  else if (no->check_scantimeout())
    timeout = no->get_scantimeout();
  
  threads = 1;
  delay = 0;

  thread_pool pool(threads);
  for (auto &port : no->get_ports()) {
    nanodelay(delay);
    futures.emplace_back(pool.enqueue(NESCASCAN_port, &ip4.sin_addr.s_addr, timeout, t, port, no));
    if (futures.size() >= static_cast<size_t>(threads)) {
      for (auto& future : futures)
        future.get();
      futures.clear();
    }
  }
  for (auto& future : futures)
    future.get();
}

void NESCAPING_thread(NESCATARGET *t, NESCAOPTS *no)
{
  double rtt = -1;
  u32 dst;
  size_t i;

  dst = inet_addr(t->ip.c_str());
  goto start;

check:
  if (rtt != -1) {
    stop.lock();
    t->rtt = rtt;
    t->good = true;
    stop.unlock();
    return;
  }
  else {
    t->rtt = -1;
    return;
  }

start:
  if (no->check_echoping() && rtt == -1)
    rtt = nescaping(no, dst, ICMP_PING_ECHO);
  if (no->check_ackping() && rtt == -1) {
    for (i = 0; i < no->get_ackports().size(); i++) {
      rtt = nescaping(no, dst, TCP_PING_ACK);
      if (rtt != -1)
        break;
    }
  }
  if (no->check_synping() && rtt == -1) {
    for (i = 0; i < no->get_synports().size(); i++) {
      rtt = nescaping(no, dst, TCP_PING_SYN);
      if (rtt != -1)
        break;
    }
  }
  if (no->check_infoping() && rtt == -1)
    rtt = nescaping(no, dst, ICMP_PING_INFO);
  if (no->check_timeping() && rtt == -1)
    rtt = nescaping(no, dst, ICMP_PING_TIME);
  if (no->check_initping() && rtt == -1) {
    rtt = nescaping(no, dst, SCTP_INIT_PING);
    for (i = 0; i < no->get_initports().size(); i++) {
      rtt = nescaping(no, dst, SCTP_INIT_PING);
      if (rtt != -1)
        break;
    }
  }
  if (no->check_udpping() && rtt == -1) {
    for (i = 0; i < no->get_udpports().size(); i++) {
      rtt = nescaping(no, dst, UDP_PING);
      if (rtt != -1)
        break;
    }
  }

  goto check;
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

ssize_t sendprobe(int fd, NESCAOPTS *no, const u32 dst, u16 dstport, u8 type)
{
  struct sockaddr_in dest;
  u32 pktlen;
  u8 *pkt;

  dest.sin_addr.s_addr = dst;
  dest.sin_family = AF_INET;

  switch (type) {
    case ICMP_PING_ECHO:
    case ICMP_PING_INFO:
    case ICMP_PING_TIME:
      pkt = icmp4probe(no, dst, type, &pktlen);
      break;
    case SCTP_COOKIE_SCAN:
    case SCTP_INIT_SCAN:
    case SCTP_INIT_PING:
      pkt = sctp4probe(no, dst, dstport, type, &pktlen);
      break;
    case UDP_PING:
    case UDP_SCAN:
      pkt = udp4probe(no, dst, dstport, type, &pktlen);
      break;
    default:
      pkt = tcp4probe(no, dst, dstport, type, &pktlen);
      break;
  }

  nescapktlog(pkt, pktlen, no);
  return (ip4_send(NULL, fd, &dest, no->get_mtu(), pkt, pktlen));
}

int readscan(const u32 dst, u8 *pkt, u8 type)
{
  if (type == SCTP_INIT_SCAN || type == SCTP_COOKIE_SCAN || type == SCTP_INIT_PING) {
    const struct sctp_hdr *sctp = (struct sctp_hdr*)(pkt + (ip4eth_len));
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
    const struct ip4_hdr *ip = (struct ip4_hdr*)(pkt + (ethhdr_len));
    if (ip->proto == IPPROTO_ICMP) {
      const struct icmp4_hdr *icmp = (struct icmp4_hdr*)(pkt + (ip4eth_len));
      if (icmp->type == 3 && icmp->code == 3)
        return PORT_CLOSED;
    }
    else if (ip->proto == IPPROTO_UDP) /* its real? */
      return PORT_OPEN;
    else
      return PORT_FILTER;
  }
  else {
    const struct tcp_hdr *tcp = (struct tcp_hdr*)(pkt + (ip4eth_len));
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

u8 *recvpacket(const u32 dst, u8 type, nescadelay_t timeoutms, double *rtt, NESCAOPTS *no)
{
  struct readfiler rf;
  struct sockaddr_in dest;
  int read = -1;
  u8 *res;
  u8 proto = 0;
  u8 secondproto = 0;
  size_t pktlen;

  switch (type) {
    case ICMP_PING_ECHO:
    case ICMP_PING_INFO:
    case ICMP_PING_TIME:
      proto = IPPROTO_ICMP;
      break;
    case SCTP_INIT_SCAN:
    case SCTP_INIT_PING:
    case SCTP_COOKIE_SCAN:
      proto = IPPROTO_SCTP;
      break;
    case UDP_PING:
    case UDP_SCAN:
      proto = IPPROTO_UDP;
      secondproto = IPPROTO_ICMP;
      break;
    default:
      proto = IPPROTO_TCP;
      break;
  }

  dest.sin_family = AF_INET;
  dest.sin_addr.s_addr = dst;
  rf.protocol = proto;
  rf.second_protocol = secondproto;
  rf.ip = (struct sockaddr_storage*)&dest;

  res = (u8*)calloc(RECV_BUFFER_SIZE, sizeof(u8));
  if (!res)
    return NULL;

  read = read_packet(&rf, timeoutms, &res, &pktlen, rtt);
  if (read == -1) {
    free(res);
    return NULL;
  }
  
  return res;
}

double nescaping(NESCAOPTS *no, const u32 dst, u8 type)
{
  ssize_t send;
  double res;
  u8 *pkt;
  int fd;

  fd = nescasocket;
  if (fd == -1)
    return -1;
  send = sendprobe(fd, no, dst, 0, type);
  close(fd);
  if (send == -1)
    return -1;
  pkt = recvpacket(dst, type, no->get_pingtimeout(), &res, no);
  if (!pkt)
    return -1;
  if (!readping(dst, pkt, type))
    return -1;

  return res;
}

bool readping(const u32 dst, u8 *pkt, u8 type)
{
  u8 icmptype;
  u8 tcpflags = 0;

  if (type == ICMP_PING_ECHO || type == ICMP_PING_TIME || type == ICMP_PING_INFO) {
    const struct icmp4_hdr *icmp = (struct icmp4_hdr *)(pkt + (ip4eth_len));
    icmptype = icmp->type;
    if (type == ICMP_PING_TIME && icmptype == ICMP4_TIMESTAMPREPLY)
      return true;
    if (type == ICMP_PING_ECHO && icmptype == ICMP4_ECHOREPLY)
      return true;
    if (type == ICMP_PING_INFO && icmptype == ICMP4_INFO_REPLY)
      return true;
  }
  if (type == TCP_PING_ACK || type == TCP_PING_SYN) {
    const struct tcp_hdr *tcp = (struct tcp_hdr*)(pkt + (ip4eth_len));
    tcpflags = tcp->th_flags;
    if (type == TCP_PING_ACK && tcpflags == TCP_FLAG_RST)
      return true;
    if (type == TCP_PING_SYN && tcpflags)
      return true;
  }
  if (type == SCTP_INIT_PING) {
    const struct sctp_hdr *sctp = (struct sctp_hdr*)(pkt + (ip4eth_len));
    if (sctp->srcport)
      return true;
  }
  if (type == UDP_PING) {
    const struct ip4_hdr *ip = (struct ip4_hdr*)(pkt + (ethhdr_len));
    if (ip->proto == IPPROTO_ICMP) {
      const struct icmp4_hdr *icmp = (struct icmp4_hdr*)(pkt + (ip4eth_len));
      if (icmp->type == 3 && icmp->code == 3)
        return true;
    }
    if (ip->proto == IPPROTO_UDP)
      return true;
  }
  
  return false;
}

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

