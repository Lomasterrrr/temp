#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/bpf.h>
#include <net/if.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 4096

void process_packet(unsigned char* buffer, int size) {
    struct ether_header* eth = (struct ether_header*) buffer;
    if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
        struct ip* iph = (struct ip*)(buffer + sizeof(struct ether_header));
        char src_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(iph->ip_src), src_ip, INET_ADDRSTRLEN);
        printf("Received packet from: %s\n", src_ip);
    }
}

int main() {
    int bpf;
    char bpf_device[11];
    int i = 0;

    // Find a BPF device
    for (i = 0; i < 10; i++) {
        snprintf(bpf_device, sizeof(bpf_device), "/dev/bpf%d", i);
        bpf = open(bpf_device, O_RDWR);
        if (bpf != -1) {
            break;
        }
    }

    if (bpf == -1) {
        perror("Cannot open BPF device");
        return 1;
    }

    // Set the network interface to capture packets
    struct ifreq ifr;
    strncpy(ifr.ifr_name, "em0", sizeof(ifr.ifr_name) - 1);  // Replace "em0" with your interface name
    if (ioctl(bpf, BIOCSETIF, &ifr) == -1) {
        perror("BIOCSETIF error");
        return 1;
    }

    // Set immediate mode
    int immediate = 1;
    if (ioctl(bpf, BIOCIMMEDIATE, &immediate) == -1) {
        perror("BIOCIMMEDIATE error");
        return 1;
    }

    // Set the buffer length
    int buf_len = BUFFER_SIZE;
    if (ioctl(bpf, BIOCSBLEN, &buf_len) == -1) {
        perror("BIOCSBLEN error");
        return 1;
    }

    unsigned char buffer[BUFFER_SIZE];

    while (1) {
        int packet_len = read(bpf, buffer, sizeof(buffer));
        if (packet_len == -1) {
            perror("BPF read error");
            return 1;
        }
        process_packet(buffer, packet_len);
    }

    close(bpf);
    return 0;
}
