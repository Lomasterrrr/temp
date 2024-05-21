/*
 * LIBNCSOCK & NESCA4
 *   Сделано от души 2023.
 * Copyright (c) [2023] [lomaster]
 * SPDX-License-Identifier: BSD-3-Clause
*/

#ifndef READPKT_HEADER
#define READPKT_HEADER

#include <stdarg.h>
#include "igmp.h"
#include "ip.h"
#include "eth.h"
#include "sctp.h"
#include "arp.h"
#include "tcp.h"
#include "udp.h"
#include "icmp.h"
#include "utils.h"

#include "../libpcap/pcap/pcap.h"
#include "../ncsock-config.h"
#include "sys/types.h"
#include "sys/nethdrs.h"

#define RECV_BUFFER_SIZE 60000

#ifndef MIN
# define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif
#ifndef MAX
# define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

#define TIMEVAL_SUBTRACT(a, b)                                                 \
  (((a).tv_sec - (b).tv_sec) * 1000000 + (a).tv_usec - (b).tv_usec)

#define LOW_DETAIL     1
#define MEDIUM_DETAIL  2
#define HIGH_DETAIL    3

#if defined(MACOSX) || (defined(FREEBSD) && (__FreeBSD_version < 500000)) || \
defined(SOLARIS_BPF_PCAP_CAPTURE) || defined(OPENBSD) || defined(SOLARIS)
  #define pcap_selectable_fd_valid 0
  #define my_pcap_get_selectable_fd(p) \
    -1
#else
  #define pcap_selectable_fd_valid 1
  #define my_pcap_get_selectable_fd(p) \
    pcap_get_selectable_fd(p)
#endif

#define CHECK_FD_OP(_Op, _Ctx) _Ctx _Op(fd, fds);
#define MAX_LINK_HEADERSZ 24

static inline void checked_fd_set(int fd, fd_set *fds) {
  CHECK_FD_OP(FD_SET, /**/);
}

__BEGIN_DECLS

struct readfiler {
  struct sockaddr_storage *ip;
  u8 protocol;
  u8 second_protocol;
};

struct abstract_iphdr {
  u8 version, proto, ttl;
  struct sockaddr_storage src, dst;
  u32 ipid;
};

struct link_header {
  int datalinktype;
  int headerlen;
  u8 header[MAX_LINK_HEADERSZ];
};

int         read_packet(eth_t *eth, struct readfiler *rf, long long timeoutns, u8 **buffer, size_t *pktlen, double *rtt);
const char *read_ippktinfo(const u8 *pkt, u32 len, int detail);

const u8 *read_ippcap(pcap_t *p, u32 *pktlen, long long timeout, double *rtt,
                      struct link_header *linknfo, bool validate);

bool read_acallback_any(const u8 *pkt, const struct pcap_pkthdr *hdr,
                        int datalink, size_t offset);
bool read_acallback_ip(const u8 *pkt, const struct pcap_pkthdr *hdr,
                       int datalink, size_t offset);

pcap_t *read_util_pcapopenlive(const char *device, int snaplen, int promisc, long long timeout);
int     read_util_pcapfilter(pcap_t *p, const char *bpf, ...);
bool    read_util_pcapread(pcap_t *p, long long timeout,
			   bool (*accept_callback)(const u8 *,
						   const struct pcap_pkthdr *, int,
						   size_t),
			   const u8 **pkt, struct pcap_pkthdr **head, double *rtt,
			   int *datalink, size_t *offset);
int    read_util_pcapselect(pcap_t *p, long long timeout);

const bool  read_util_validate_tcp(const u8 *tcpc, unsigned len);
const bool  read_util_validate_pkt(const u8 *ipc, unsigned *len);
const int   read_util_datalinkoffset(int datalink);
const void *read_util_getip4data_pr(const void *pkt, u32 *len,
                                    struct abstract_iphdr *hdr,
                                    bool upperlayer_onl);
const void *read_util_getip6data_pr(const struct ip6_hdr *ip6, u32 *len,
                                    u8 *nxt, bool upperlayer_only);
const void *read_util_ip4getdata_up(const struct ip4_hdr *ip, u32 *len);
const void *read_util_icmp4getdata(const struct icmp4_hdr *icmp, u32 *len);
const void *read_util_icmp6getdata(const struct icmp6_hdr *icmp, u32 *len);
char *read_util_nexthdrtoa(u8 nxthdr, int acronym);
void read_util_tcpoptinfo(u8 *optp, int len, char *result, int bufsize);
char *read_util_fmtipopt(const u8 *ipopt, int ipoptlen);
#define read_util_ip4getdata(pkt, len, hdr)                                    \
  read_util_getip4data_pr((pkt), (len), (hdr), true)
#define read_util_ip4getdata_any(pkt, len, hdr)                                \
  read_util_getip4data_pr((pkt), (len), (hdr), false)
#define read_util_ip6getdata(ip6, len, nxt)                                    \
  read_util_getip6data_pr((ip6), (len), (nxt), true)
#define read_util_ip6getdata_any(ip6, len, nxt)                                \
  read_util_getip6data_pr((ip6), (len), (nxt), false)



/* OLD */
struct ip4_hdr*   ext_iphdr(u8 *buf);
struct tcp_hdr*  ext_tcphdr(u8 *buf);
struct udp_hdr*  ext_udphdr(u8 *buf);
struct icmp4_hdr* ext_icmphdr(u8 *buf);
struct igmp_hdr* ext_igmphdr(u8 *buf);

void print_ipdr(const struct ip4_hdr *iphdr);
void print_tcphdr(const struct tcp_hdr *tcphdr);
void print_udphdr(const struct udp_hdr *udphdr);
void print_icmphdr(const struct icmp4_hdr *icmphdr);
void print_payload(const u8 *payload, int len);
void print_payload_ascii(const u8 *payload, int len);

__END_DECLS


#endif


