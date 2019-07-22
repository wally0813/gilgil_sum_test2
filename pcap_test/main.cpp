#include <pcap.h>
#include <stdio.h>
#include <stdint.h>

struct ether_addr
{
        u_char ether_addr_octet[6];
};
 
struct ether_header
{
        struct  ether_addr ether_dhost;
        struct  ether_addr ether_shost;
        uint16_t ether_type;
};


struct ip_header
{
        u_char ip_header_len:4;
        u_char ip_version:4;
        u_char ip_tos;
        uint16_t ip_total_length;
        uint16_t ip_id;
        u_char ip_frag_offset:5;
        u_char ip_more_fragment:1;
        u_char ip_dont_fragment:1;
        u_char ip_reserved_zero:1;
        u_char ip_frag_offset1;
        u_char ip_ttl;
        u_char ip_protocol;
        uint16_t ip_checksum;
        uint8_t ip_srcaddr[4];
        uint8_t ip_destaddr[4];
};
 
struct tcp_header
{
        uint16_t source_port;
        uint16_t dest_port;
        uint32_t sequence;
        uint32_t acknowledge;
        u_char ns:1;
        u_char reserved_part1:3;
        u_char data_offset:4;
        u_char fin:1;
        u_char syn:1;
        u_char rst:1;
        u_char psh:1;
        u_char ack:1;
        u_char urg:1;
        u_char ecn:1;
        u_char cwr:1;
        uint16_t window;
        uint16_t checksum;
        uint16_t urgent_pointer;
};
 
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
  struct ether_header *eh;
  struct ip_header *ih;
  struct tcp_header *th;
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

    eh = (struct ether_header *)packet;
    ih = (struct ip_header *)(packet+sizeof(struct ether_header));
    int ih_len = ih->ip_header_len;

    printf("D-mac ");
    print_mac((uint8_t *)(&eh->ether_dhost));

    printf("S-mac ");
    print_mac((uint8_t *)(&eh->ether_shost));

    if (my_ntohs(eh->ether_type) == 0x0800){

	    printf("S-ip ");
	    print_ip((uint8_t *)(&ih->ip_srcaddr));
	    
	    printf("D-ip ");
	    print_ip((uint8_t *)(&ih->ip_destaddr));
    
	    if (ih->ip_protocol == 0x06){
   
		    th = (struct tcp_header *)(packet+sizeof(struct ether_header)+sizeof(struct ip_header));

		    printf("S-port ");
		    print_port((uint8_t *)(&th->source_port));
    
		    printf("D-port ");
		    print_port((uint8_t *)(&th->dest_port));

		    off = th->data_offset*4;
		    d_len = header->caplen-sizeof(ether_header)-ih_len-off;
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
