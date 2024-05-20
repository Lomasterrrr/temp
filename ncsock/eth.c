/*
 * LIBNCSOCK & NESCA4
 *   Сделано от души 2023.
 * Copyright (c) [2023] [lomaster]
 * Copyright (c) [2000] Dug Song <dugsong@monkey.org>
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "include/eth.h"

#if (defined(IS_BSD))
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <net/if.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/sysctl.h>
#include <net/route.h>
#include <net/if_dl.h>

#define BPF_DEV "/dev/bpf0"
#ifndef ETHER_ADDR_LEN
  #define ETHER_ADDR_LEN 6
#endif

typedef unsigned char uchar;
typedef long long vlong;

static uchar *pktbuf = NULL;
static int pktbufsz = 0;

struct eth_handle { int fd; char device[16]; };

int eth_fd(eth_t *e) {
  return e->fd;
}

eth_t *eth_open(const char *device)
{
    char m;
    int fd = -1;
    struct bpf_version bv;
    unsigned bufsize, linktype;
    char bpf_device[sizeof BPF_DEV];
    struct ifreq ifr;

    struct bpf_insn insns[] = {
        BPF_STMT(BPF_RET | BPF_K, (u_int)-1),  // Пропустить все пакеты
    };

    struct bpf_program bpf_program = {
        .bf_len = sizeof(insns) / sizeof(struct bpf_insn),
        .bf_insns = insns,
    };

    strncpy(bpf_device, BPF_DEV, sizeof BPF_DEV);

    /* find a bpf device we can use, check /dev/bpf[0-9] */
    for (m = '0'; m <= '9'; m++) {
        bpf_device[sizeof(BPF_DEV)-2] = m;

        if ((fd = open(bpf_device, O_RDWR)) > 0)
            break;
    }

    if (fd < 0) {
        perror("open");
        return NULL;
    }

    if (ioctl(fd, BIOCVERSION, &bv) < 0) {
        perror("BIOCVERSION");
        goto bad;
    }

    if (bv.bv_major != BPF_MAJOR_VERSION || bv.bv_minor < BPF_MINOR_VERSION) {
        fprintf(stderr, "kernel bpf filter out of date\n");
        goto bad;
    }

    /*
     * Try finding a good size for the buffer; 65536 may be too
     * big, so keep cutting it in half until we find a size
     * that works, or run out of sizes to try.
     *
     */
    for (unsigned v = 65536; v != 0; v >>= 1) {
        (void) ioctl(fd, BIOCSBLEN, (caddr_t)&v);

        (void)strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
        if (ioctl(fd, BIOCSETIF, (caddr_t)&ifr) >= 0)
            break;  /* that size worked; we're done */

        if (errno != ENOBUFS) {
            fprintf(stderr, "BIOCSETIF: %s: %s\n", device, strerror(errno));
            goto bad;
        }
    }
    
    if (pktbufsz == 0) {
        fprintf(stderr, "BIOCSBLEN: %s: No buffer size worked\n", device);
        goto bad;
    }

    /* Allocate memory for the packet buffer */
    if ((pktbuf = malloc(pktbufsz)) == NULL) {
        perror("malloc");
        goto bad;
    }

    /* Don't wait for buffer to be full or timeout */
    unsigned v = 1;
    if (ioctl(fd, BIOCIMMEDIATE, &v) < 0) {
        perror("BIOCIMMEDIATE");
        goto bad;
    }

    /* Only read incoming packets */
    v = 0;
    if (ioctl(fd, BIOCSSEESENT, &v) < 0) {
        perror("BIOCSSEESENT");
        goto bad;
    }

    /* Don't complete ethernet hdr */
    v = 1;
    if (ioctl(fd, BIOCSHDRCMPLT, &v) < 0) {
        perror("BIOCSHDRCMPLT");
        goto bad;
    }

    /* Get the data link layer type. */
    if (ioctl(fd, BIOCGDLT, (caddr_t)&v) < 0) {
        perror("BIOCGDLT");
        goto bad;
    }
    linktype = v;

    /* Get the filter buf size */
    if (ioctl(fd, BIOCGBLEN, (caddr_t)&v) < 0) {
        perror("BIOCGBLEN");
        goto bad;
    }
    bufsize = v;

    if (ioctl(fd, BIOCSETF, &bpf_program) < 0) {
        perror("BIOSETF");
        goto bad;
    }

    eth_t *e = malloc(sizeof(eth_t));
    if (!e) {
        perror("malloc");
        goto bad;
    }

    e->fd = fd;
    strncpy(e->device, device, sizeof(e->device));
    return e;

bad:
    if (pktbuf) {
        free(pktbuf);
        pktbuf = NULL;
    }
    if (fd >= 0) {
        close(fd);
    }
    return NULL;
}

eth_t *eth_close(eth_t *e)
{
    if (e != NULL) {
        if (e->fd >= 0)
            close(e->fd);
        free(e);
    }
    return NULL;
}

ssize_t eth_send(eth_t *e, const void *buf, size_t len)
{
    return write(e->fd, buf, len);
}

ssize_t eth_read(eth_t *e, u8 *buf, ssize_t len) 
{
    register struct bpf_hdr *bh;
    register int pktlen, retlen;
    
    if (pktbufsz <= 0) {
        if ((pktbufsz = read(e->fd, pktbuf, pktbufsz)) < 0) {
            perror("read");
            return -1;
        }
        pktbp = pktbuf;
    }

    bh = (struct bpf_hdr *) pktbp;
    retlen = (int) bh->bh_caplen;
    /* This memcpy() is currently needed */ 
    memcpy(buf, (void *)(pktbp + bh->bh_hdrlen), retlen > len ? len : retlen);
    pktlen = bh->bh_hdrlen + bh->bh_caplen; 
    
    pktbp = pktbp + BPF_WORDALIGN(pktlen);
    pktbufsz -= (int) BPF_WORDALIGN(pktlen);

    return retlen;
}

#endif
#if defined(IS_LINUX)
#include "include/sys/debianfix.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <stdbool.h>

struct eth_handle { int fd; struct ifreq ifr; struct sockaddr_ll sll; };

int eth_fd(eth_t *e) {
  return e->fd;
}

eth_t *eth_open(const char *device)
{
  eth_t *e;

  e = calloc(1, sizeof(*e));
  if (!e)
    return e;

  if ((e->fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    return (eth_close(e));

  _strlcpy(e->ifr.ifr_name, device, sizeof(e->ifr.ifr_name));
  if (ioctl(e->fd, SIOCGIFINDEX, &e->ifr) < 0)
    return (eth_close(e));

  e->sll.sll_family = AF_PACKET;
  e->sll.sll_ifindex = e->ifr.ifr_ifindex;

  return e;
}

ssize_t eth_send(eth_t *e, const void *buf, size_t len)
{
  struct eth_hdr *eth;

  eth = (struct eth_hdr*)buf;
  e->sll.sll_protocol = eth->type;

  return (sendto(e->fd, buf, len, 0,
        (struct sockaddr*)&e->sll, sizeof(e->sll)));
}

ssize_t eth_read(eth_t *e, u8 *buf, ssize_t len)
{
  return recv(e->fd, buf, len, 0);
}

eth_t *eth_close(eth_t *e)
{
  if (e) {
    if (e->fd >= 0)
      close(e->fd);
    free(e);
  }
  return NULL;
}
#endif
