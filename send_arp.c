#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <stdint.h>
#include <sys/socket.h>
#include "send_arp.h"


/* Ethernet header */

struct __attribute__((packed)) etherhdr {
	u_char dst[ETHER_ADDR_LEN];
	u_char src[ETHER_ADDR_LEN];
	u_int16_t ether_type; // ARP : 0x0806
};

/* ARP Header, (assuming Ethernet+IPv4)            */ 
#define ARP_REQUEST 1   /* ARP Request             */ 
#define ARP_REPLY 2     /* ARP Reply               */ 
struct __attribute__((packed)) arphdr { 
    u_int16_t htype;    /* Hardware Type           */ 
    u_int16_t ptype;    /* Protocol Type           */ 
    u_char hlen;        /* Hardware Address Length */ 
    u_char plen;        /* Protocol Address Length */ 
    u_int16_t oper;     /* Operation Code          */ 
    u_char sha[6];      /* Sender hardware address */ 
    u_char spa[4];      /* Sender IP address       */ 
    u_char tha[6];      /* Target hardware address */ 
    u_char tpa[4];      /* Target IP address       */ 
}; 

void print_mac(u_char *mac_addr){
	for(int i=0;i<ETHER_ADDR_LEN;i++){
		printf("%02x",*(mac_addr+i));
		if(i<5) printf(":");
		else printf("\n");
	}
}

void arp_broad(pcap_t *handle, u_char *mac_addr, struct in_addr *senderIP, struct in_addr *targetIP){
	u_char* packet;
	struct etherhdr ether,*recv_ether;
	struct arphdr arp_h,*recv_arp_h;
	u_char* recv_packet;
	struct pcap_pkthdr *header;
	int packet_len;
	int flag;
	struct in_addr recv_IP;
	u_char* recv_MAC;
	memcpy(ether.src,mac_addr,ETHER_ADDR_LEN);
	memcpy(ether.dst,"\xff\xff\xff\xff\xff\xff",ETHER_ADDR_LEN);
	ether.ether_type = htons(0x0806);
	printf("\n\t[+] Ethernet header\n");
	printf("\t\t[-] Destination MAC : ");
	print_mac(ether.dst);
	printf("\t\t[-] Source MAC : ");
	print_mac(ether.src);
	printf("\t\t[-] ethernet type : 0x%x\n",ntohs(ether.ether_type));

	arp_h.htype = htons(0x0001);
	arp_h.ptype = htons(ETHERTYPE_IP);
	arp_h.hlen = ETHER_ADDR_LEN;
	arp_h.plen = 4;
	arp_h.oper = htons(ARP_REQUEST);
	memcpy(arp_h.sha,mac_addr,sizeof(arp_h.sha));
	memcpy(arp_h.spa,senderIP,sizeof(arp_h.spa));
	memcpy(arp_h.tha,"\x00\x00\x00\x00\x00\x00",sizeof(arp_h.tha));
	memcpy(arp_h.tpa,targetIP,sizeof(arp_h.tpa));

	printf("\n\t[+] IP information\n");
	printf("\t\tsenderIP : %s // hex : 0x%x\n",inet_ntoa(*senderIP),htonl(senderIP->s_addr));
	printf("\t\ttargetIP : %s // hex : 0x%x\n",inet_ntoa(*targetIP),htonl(targetIP->s_addr));

	printf("\n\n\t[+] ARP header information\n");
	printf("\t\thtype : 0x%x\n",ntohs(arp_h.htype));
	printf("\t\tptype : 0x%x\n",ntohs(arp_h.ptype));
	printf("\t\thlen : %d\n",arp_h.hlen);
	printf("\t\tplen : %d\n",arp_h.plen);
	printf("\t\toper : %x\n",ntohs(arp_h.oper));
	printf("\t\tsender mac : "); print_mac(arp_h.sha);
	printf("\t\tsender IP : 0x"); for(int i=0;i<4;i++) printf("%02x",arp_h.spa[i]); printf("\n");
	printf("\t\ttarget MAC : "); print_mac(arp_h.tha);
	printf("\t\ttarget IP : 0x"); for(int i=0;i<4;i++) printf("%02x",arp_h.tpa[i]); printf("\n");

	packet = (u_char*)malloc(sizeof(ether)+sizeof(arp_h));
	memcpy(packet,&ether,sizeof(ether));
	memcpy(packet+sizeof(ether),&arp_h,sizeof(arp_h));
	packet_len = sizeof(ether) + sizeof(arp_h);
	
	printf("\n[+] packet to send\n");
	for(int i=0;i<sizeof(ether)+sizeof(arp_h);i++){
		if(i != 0 && i%16 == 0)
			printf("\n");
		printf("%02x ",*(packet+i));
	}
	printf("end\n");

	while(1){
		if(pcap_sendpacket(handle,packet,packet_len) == 0)
			break;
	}

	printf("\n[+] arp request completed!\n\n");
	while(1){
		flag = pcap_next_ex(handle,&header,&recv_packet);
		if(flag == 0){
			printf("[-] time out! sending packet...\n");
			if(pcap_sendpacket(handle,packet,packet_len) !=0){
				printf("[-] failed... restart the program!\n");
				exit(1);
			}
			else
				continue;
		}
		else if(flag < 0){
			printf("[-] fail to receive packet... restart the program!\n");
			exit(1);
		}


	for(int i=0;i<sizeof(ether)+sizeof(arp_h);i++){
		if(i != 0 && i%16 == 0)
			printf("\n");
		printf("%02x ",*(recv_packet+i));
	}
	printf("end\n");
		printf("\n[-] success to receive packet!\n");
		recv_ether = (struct etherhdr*)recv_packet;
		if(htons(recv_ether->ether_type) != 0x0806){
			printf("[-] reply ether type is not arp!\n");
			printf("ether type : 0x%x\n",ntohs(recv_ether->ether_type));
			continue;
		}
		recv_arp_h = (struct arphdr*)(recv_packet + sizeof(struct etherhdr));
		
		if(htons(recv_arp_h->htype) != 1 || htons(recv_arp_h->ptype) != 0x0800 || ntohs(recv_arp_h->oper) != ARP_REPLY){
			printf("[-] this packet is not arp reply packet!\n");
			printf("hardware type : 0x%x\nARP type : 0x%x // ARP REPLY : 0x%x\n",ntohs(recv_arp_h->htype),ntohs(recv_arp_h->oper),ARP_REPLY);
			continue;
		}

		printf("ARP type : 0x%x // ARP REPLY : 0x%x\n",ntohs(recv_arp_h->oper),ARP_REPLY);
		if(memcmp(recv_arp_h->spa,senderIP,sizeof(senderIP))){
			printf("[-] senderIP not match!\n");
			printf("\t[+] received arp header IP : ");
			for(int i=0;i<4;i++) printf("%02x", recv_arp_h->spa[i]); printf("\n");
			printf("\t[+] sender IP : ");
			printf("%x\n",htonl(senderIP->s_addr));
			continue;
		}
		
		memcpy(&recv_IP,recv_arp_h->spa,sizeof(recv_IP));
		printf("\n[+] result\n");
		printf("\t[-] reply IP : %s\n",inet_ntoa(recv_IP));
		printf("\t[-] reply MAC : "); print_mac(recv_arp_h->sha);
		printf("\nDone!\n");
		
		break;
	}
}

int main(int argc, char* argv[])
{
	char *dev;
	pcap_t *handle, *packet_ptr;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_char *packet;
	u_char *my_mac;
	struct in_addr senderIP, targetIP, myIP;
	u_char addr[4];
	u_char *buf;

	struct in_addr in;

	struct etherhdr ether;
	struct arphdr arp;

	if(argc < 4){
		printf("[+] Usage : %s [interface] [sender_ip] [target_ip]\n",argv[0]);
		exit(1);
	}
	
	dev = argv[1];
	printf("\n[+] device : %s\n",dev);
	my_mac = GetSvrMacAddress(dev);
	printf("[+] my MAC : "); print_mac(my_mac);

	if(s_get_IPAddress(dev,addr)>0){
		printf("[+] my IP : %d.%d.%d.%d // hex : ",(int)addr[0],(int)addr[1],(int)addr[2],(int)addr[3]);
	}

	buf = (char *)malloc(sizeof(addr));
	sprintf(buf,"%d.%d.%d.%d",(int)addr[0],(int)addr[1],(int)addr[2],(int)addr[3]);
	inet_pton(AF_INET,buf,&myIP.s_addr);
	printf("0x%X\n",ntohl(myIP.s_addr));
	free(buf);

	inet_pton(AF_INET,argv[2],&senderIP.s_addr);
	inet_pton(AF_INET,argv[3],&targetIP.s_addr);

	handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
	if(handle == NULL){
		printf("[+] cannot open device!\n");
		exit(1);
	}
	//arp_broad(handle,my_mac,&senderIP,&targetIP);
	arp_broad(handle,my_mac,&myIP,&senderIP);
	printf("\n[+] Done!\n");		
	return 0;
}






