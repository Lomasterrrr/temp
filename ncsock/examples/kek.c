#include "../include/readpkt.h"
#include "../include/log.h"
#include "../include/tcp.h"

int main(void){
  pcap_t *t;
  int fd;
    
  t = read_util_pcapopenlive("enp7s0", 100, 1, 1);
  if (!t)
    err(1, "fuck open");
  read_util_pcapfilter(t, "tcp and src host 74.125.131.102");
  
  fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  tcp4_qsend_pkt(fd, "192.168.1.34", "74.125.131.102", 200, 443, TCP_FLAG_SYN, NULL, 0);

  double rtt;
  u32 pktlen;
  struct ip4_hdr *ip;
  struct tcp_hdr *tcp;
  struct abstract_iphdr hdr;
  const void *data = NULL;
  
  ip = (struct ip4_hdr*)read_ippcap(t, &pktlen, 1e+9, &rtt, NULL, true);
  printf("pktlen = %d\n", pktlen);
  printf("rtt = %f\n", rtt);
  
  data = read_util_ip4getdata(ip, &pktlen, &hdr);
  if (data == NULL)
    err(1, "data fuck");
  tcp = (struct tcp_hdr*)data;
  if (tcp->th_flags == 0x12)
    printf("%d, yes!\n", ip->proto);
  pcap_close(t);

  return 0;
}
