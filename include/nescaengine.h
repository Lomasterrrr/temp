#ifndef NESCAENGINE_HEADER
#define NESCAENGINE_HEADER

#include <cstdlib>
#include <ctime>
#include <mutex>
#include <chrono>
#include <unordered_map>
#include <vector>
#include <iostream>
#include <string>
#include <functional>

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
#include "../ncsock/include/ncpcap.h"

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

#define GETELAPSED(start, end)                                                 \
  (((end).tv_sec - (start).tv_sec) * 1000000000LL + (end).tv_nsec -            \
   (start).tv_nsec)

void NESCARSLV_thread(NESCATARGET *t, NESCAOPTS *no);
void NESCAHTTP_thread(NESCATARGET *t, NESCAOPTS *no);
void NESCAPROC_thread(NESCATARGET *t, NESCAOPTS *no);

u8  *tcp4probe(NESCAOPTS *no, const u32 dst, u16 dstport, u8 type, u32 *pktlen);
u8  *icmp4probe(NESCAOPTS *no, const u32 dst, u8 type, u32 *pktlen);
u8  *sctp4probe(NESCAOPTS *no, const u32 dst, u16 dstport, u8 type, u32 *pktlen);
u8  *udp4probe(NESCAOPTS *no, const u32 dst, u16 dstport, u8 type, u32 *pktlen);

bool readping(u8 *pkt, u32 pktlen, int type);
int  readscan(u8 *pkt, u32 pktlen, int type);

/* Структура которая представляет абстракцию отправляемого пакета через
 * NESCARAWSEND.
 */
struct NESCARAWPACKET_SEND {
  struct sockaddr_storage dst; int mtu; u8 *pkt; u32 pktlen;
};

/* Структура которая представляет абстракцию принимаемого пакета через
 * NESCARAWRECV.
 */
struct NESCARAWPACKET_RECV {
  u8 *pkt; u32 pktlen; long long ns; double rtt; struct link_header nfo;
  std::string dst; std::string proto; int type; u16 port; struct timeval start, end;
};

class NESCARAWSEND
{
  /* Здесь currentfd это текущий номер сокета, а changefd
   * через какое количество отправок нужно его поменять, а
   * totalfd общее количество сокетов, и число сколько надо
   * создать.
   */
  size_t currentfd, changefd, totalfd;

  /* Временные точки, первая начало работы отправки в целом, вторая конец. */
  struct timeval start, end;

  /* Общая статистика, где, total количество отправок,
   * er количество ошибочных отправок, ok количество
   * успешных отправок.
   */
  size_t total, ok, er;

  /* Статистика последней отправки, если она успешная то oklast
   * будет true, если нет, то false.
   */
  bool oklast;

  /* Сила трассировки пакетов (1-3), если -1 то выключено. */
  int trace;

  /* Максимальное количество отправок в секунду, если 0 то не ограничено. */
  size_t maxrate;

  /* Время последней отправки. */
  std::chrono::high_resolution_clock::time_point lastsendtime;
  
  /* Сокеты. */
  std::vector<int> fds;

  /* Отправляет пакет и каждый changefd меняет сокет, если сокеты кончились начинает с самого первого.
   * В случае успешной отправки увеличивает ok на 1, в ином случае увеличивает er на 1. Помимо этого
   * каждый вызов увеличивает total.
   */
  void sendpkt(NESCARAWPACKET_SEND *p);

  /* Открывает totalfd сокетов. */
  void initfds(void);
        
public:
  NESCARAWSEND(void);
  ~NESCARAWSEND(void);

  /* Отправляет сразу много пакетов используя потоки. */
  void NRS_loop(std::vector<NESCARAWPACKET_SEND> *pkts);
  
  /* Отправляет один пакет. */
  void NRS_next(NESCARAWPACKET_SEND *pkt);
  
  /* Устанавливает количество сокетов. */
  void NRS_fdnum(size_t num);

  /* Устанавливает число пакетов после которого надо менять сокет. */
  void NRS_nextfd(size_t num);

  /* Устанавливает уровень трассировки пакетов, -1 это без. */
  void NRS_trace(int level);

  /* Устанавливает максимальное количество отправок в секунду, если 0 то не ограничено. */
  void NRS_maxrate(size_t num);
  
  /* Выводит статистику отправки. */
  void NRS_stats(void);

  /* Получить время всей отправки в милисекундах. */
  double NRS_getsendms(void);
};

class NESCARAWRECV
{
  /* Очередь, ключом к которой является дескриптор pcap. */
  std::unordered_map<pcap_t*, NESCARAWPACKET_RECV*> queue;

  /* Последний вызываемый или вызванный элемент очереди. */
  std::unordered_map<pcap_t*, NESCARAWPACKET_RECV*>::iterator currentqueue;

  /* Последний очищенный элемент. */
  std::unordered_map<pcap_t*, NESCARAWPACKET_RECV*>::iterator freequeue;
  
  /* Количество вызовов NRR_queue и количество успешно запушенных pcap. */
  size_t totalpcaps, activepcaps;

  /* Максимальный размер пакета, число на которое надо выделять память для буферов. */
  size_t maxpktlen;

  /* Общая статистика, где, total количество попыток чтения,
   * er количество ошибочных чтений, ok количество
   * успешных чтений.
   */
  size_t ok, er, total;

  /* Статистика последнего чтения, если оно успещное, то oklast
   * будет true, если нет, то false.
   */
  bool oklast;

  /* Уровень трассироваки пакетов, -1 это без. */
  int trace;

  /* Иницилизирует пакет - выделяет под u8 *pkt то количество памяти, сколько указано
   * в maxpktlen.
   */
  bool initpkt(NESCARAWPACKET_RECV **p);
  
public:
  NESCARAWRECV(void);
  
  /* Открывает pcap дескриптор с указанными данными, иницилизирует пакет с помощью initpkt,
   * каждый вызов увеличивает totalpcaps на 1, если pcap был успешно открыт то и увеличивает
   * activepcaps на 1. Также устанавливает указанный фильтр на открытый дескриптор pcap.
   */
  void NRR_queue(const std::string& device, const std::string &bpf, int snaplen,
		 int promisc, NESCARAWPACKET_RECV *p);

  /* Открывает сразу много pcap дескрипторов в потоках, но их значения кроме *pkts будут одинаковы,
   * также ставит bpf фильтр используя proto, src, и pkts[index]->dst. Количество потоков зависит от
   * размера pkts.
   */
  void NRR_queueloop(const std::string& device, const std::string &src, int snaplen,
		     int promisc, std::vector<NESCARAWPACKET_RECV> *pkts);

  /* Читает следующий пакет из очереди queue, в качестве дескриптора откуда будет читать пакет использует
   * первй элемент queue (ключ), в качестве буфера для сохранения пакета и информации о нем использует второй
   * элемент queue. С каждым новым запуском меняет элемент queue, его ключ, сохраняет текущую позицию в
   * currentqueue. Помимо этого каждый вызов увеличивает total, каждое успешное чтение ok, каждое не успешное er.
   */
  void NRR_next(void);

  /* Читает сразу все пакеты в потоках из очереди queue с помощью NRR_next, количество потоков зависит от количества
x   * успешно открытых pcap, (activepcaps)
   */
  void NRR_loop(void);

  /* Устанавливает уровень трассировки пакетов, -1 без. */
  void NRR_trace(int level);
  
  /* Устанавливает максимальный размер буфера для записи пакета, тоесть maxpktlen. */
  void NRR_buflen(size_t num);

  /* Выводит статистику чтения. */
  void NRR_stats(void);

  /* Очистить память у одного элемента очереди. */
  void NRR_free(void);

  /* Очистить память но в потоках и в указанном количестве, если 0 то значит всю очередь. */
  void NRR_loopfree(size_t num);  
};

class NESCARAWENGINE {
  std::vector<NESCARAWPACKET_SEND> onsend;
  std::vector<NESCARAWPACKET_RECV> forrecv;
  
  NESCAOPTS *no;
  NESCADATA2 *nd;
  u8 worktype;

  double fixrtt;

  void build_pktloop_type(std::vector<NESCATARGET*> targets, int type);
  void build_pktloop(std::vector<NESCATARGET*> targets);
  
  std::vector<int> get_types(void);
  void build_pkt(NESCATARGET *t, u16 dstport, int type);
  void read_pkts(void);
  void free_pkts(void);

public:
  NESCARAWENGINE(std::vector<NESCATARGET *> targets, NESCAOPTS *no, NESCADATA2 *nd, u8 worktype);
  ~NESCARAWENGINE(void);
};

void httpprc(NESCATARGET *t, NESCAOPTS *no);
void ftpprc(NESCATARGET *t, NESCAOPTS *no);

#endif
