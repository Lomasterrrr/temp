#ifndef NETHDRS_HEADER
#define NETHDRS_HEADER

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <sys/time.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/cdefs.h>
#include <netdb.h>
#include <errno.h>
#include <net/if.h>

#include "../../ncsock-config.h"

#if defined(IS_BSD)
  #include <sys/sysctl.h>
  #include <net/route.h>
  #include <net/if_dl.h>
  #include <net/bpf.h>
  #include <net/if_var.h>
  #include <net/if_types.h>

#elif defined(IS_LINUX)
  #include <net/if.h>
  #if __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 1
    #include <netpacket/packet.h>
    #include <net/ethernet.h>
  #else
    #include <asm/types.h>
    #include <linux/if_packet.h>
    #include <linux/if_ether.h>
  #endif
#endif
  
#endif
