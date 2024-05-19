#ifndef NESCAENGINE_HEADER
#define NESCAENGINE_HEADER

#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <netinet/in.h>
#include <chrono>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>
#include <iostream>
#include <string>

#include "../ncsock/include/eth.h"
#include "../ncsock/include/sctp.h"
#include "../ncsock/include/utils.h"
#include "../ncsock/include/arp.h"
#include "../ncsock/include/readpkt.h"
#include "../ncsock/include/utils.h"
#include "../ncsock/include/icmp.h"
#include "../ncsock/include/udp.h"
#include "../ncsock/include/dns.h"
#include "../ncsock/include/tcp.h"
#include "../ncsock/include/http.h"

#include "nescadata.h"
#include "nescathread.h"
#include "nescaopts.h"
#include "nescahttp.h"

#define ICMP_PING_ECHO            1
#define ICMP_PING_INFO            2
#define ICMP_PING_TIME            3
#define TCP_PING_SYN              4
#define TCP_PING_ACK              5
#define TCP_SYN_SCAN              6
#define TCP_XMAS_SCAN             7
#define TCP_FIN_SCAN              8
#define TCP_NULL_SCAN             9
#define TCP_ACK_SCAN              10
#define TCP_WINDOW_SCAN           11
#define TCP_MAIMON_SCAN           12
#define TCP_PSH_SCAN              13
#define SCTP_INIT_SCAN            14
#define SCTP_COOKIE_SCAN          15
#define SCTP_INIT_PING            16
#define UDP_PING                  17
#define UDP_SCAN                  18
#define ARP_PING                  19

#define PORT_OPEN                 0
#define PORT_CLOSED               1
#define PORT_FILTER               2
#define PORT_ERROR               -1
#define PORT_OPEN_OR_FILTER       3
#define PORT_NO_FILTER            4

#define nescasocket socket(AF_INET, SOCK_RAW, IPPROTO_RAW)
#define ethhdr_len  (sizeof(struct eth_hdr))
#define ip4hdr_len  (sizeof(struct ip4_hdr))
#define ip4eth_len (ethhdr_len + ip4hdr_len)

void NESCARSLV_thread(NESCATARGET *t, NESCAOPTS *no);
void NESCAPING_thread(NESCATARGET *t, NESCAOPTS *no);
void NESCASCAN_thread(NESCATARGET *t, NESCAOPTS *no);
void NESCAHTTP_thread(NESCATARGET *t, NESCAOPTS *no);
void NESCAPROC_thread(NESCATARGET *t, NESCAOPTS *no);
  
ssize_t sendprobe(int fd, NESCAOPTS *no, const u32 dst, u16 dstport, u8 type);
double  nescaping(NESCAOPTS *no, const u32 dst, u8 type);
bool    readping(const u32 dst, u8 *pkt, u8 type);
u8     *recvpacket(const u32 dst, u8 type, nescadelay_t timeoutms, double *rtt, NESCAOPTS *no);
int     readscan(const u32 dst, u8 *pkt, u8 type);

u8 *tcp4probe(NESCAOPTS *no, const u32 dst, u16 dstport, u8 type, u32 *pktlen);
u8 *icmp4probe(NESCAOPTS *no, const u32 dst, u8 type, u32 *pktlen);
u8 *sctp4probe(NESCAOPTS *no, const u32 dst, u16 dstport, u8 type, u32 *pktlen);
u8 *udp4probe(NESCAOPTS *no, const u32 dst, u16 dstport, u8 type, u32 *pktlen);

void httpprc(NESCATARGET *t, NESCAOPTS *no);
void ftpprc(NESCATARGET *t, NESCAOPTS *no);

#endif
