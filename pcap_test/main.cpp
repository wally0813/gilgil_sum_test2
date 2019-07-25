#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <libnet.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void print_mac(uint8_t *mac) {

    int i;

    for (i = 0;i < 6;i++) {
        if (i == 5) {
            printf("%02x", mac[i]);
        }
        else {
            printf("%02x:", mac[i]);
        }
    }
    printf("\n");

}
void print_ip(uint8_t *ip) {

    int i;

    for (i = 0;i < 4;i++) {
        if (i == 3) {
            printf("%d", ip[i]);
        }
        else {
            printf("%d.", ip[i]);
        }
    }
    printf("\n");
}

void print_port(uint8_t *port) {

	int i = 0;
	int p = (port[0] << 8) | port[1];
	
	printf(" %d", p);
	printf("\n");
}

void print_data(uint8_t *data, int len){

	int i = 0;

	for(i=0;i<len;i++){
		printf("%02x ",data[i]);
	}

	printf("\n");
}

uint16_t my_ntohs(uint16_t port)
{
	return (((port & 0x00ff) << 8) + ((port & 0xff00) >> 8));
}

int main(int argc, char* argv[]) {

  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  struct libnet_ethernet_hdr *eh;
  struct libnet_ipv4_hdr *ih;
  struct libnet_tcp_hdr *th;
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    int off, d_len;
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    printf("%u bytes captured\n", header->caplen);

    eh = (struct libnet_ethernet_hdr *)packet;
    ih = (struct libnet_ipv4_hdr *)(packet+sizeof(struct libnet_ethernet_hdr));
    int ih_len = ih->ip_hl;

    printf("D-mac ");
    print_mac((uint8_t *)(&eh->ether_dhost));

    printf("S-mac ");
    print_mac((uint8_t *)(&eh->ether_shost));

    if (my_ntohs(eh->ether_type) == 0x0800){

	    printf("S-ip ");
	    print_ip((uint8_t *)(&ih->ip_src));
	    
	    printf("D-ip ");
	    print_ip((uint8_t *)(&ih->ip_dst));
    
	    if (ih->ip_p == 0x06){
   
		    th = (struct libnet_tcp_hdr *)(packet+sizeof(struct libnet_ethernet_hdr)+sizeof(struct libnet_ipv4_hdr));

		    printf("S-port ");
		    print_port((uint8_t *)(&th->th_sport));
    
		    printf("D-port ");
		    print_port((uint8_t *)(&th->th_dport));

		    off = th->th_off*4;
		    d_len = header->caplen-sizeof(libnet_ethernet_hdr)-ih_len-off;
		    if (d_len > 10) d_len = 10;
		    else if (d_len < 0) continue;
		    print_data((uint8_t *)(packet+off),d_len);
    
	    }else{

		printf("IPType is not TCP protocol\n");

	    }
    }else{

	printf("EtherType is not IP protocol\n");

    }
  }

  pcap_close(handle);
  return 0;
}
