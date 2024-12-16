/*2017.8/25 Need to build DHCP_STATIC_PART_HEADER for DHCP_OFFER */

#include	<stdio.h>
#include	<string.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<poll.h>
#include	<errno.h>
#include	<signal.h>
#include	<stdarg.h>
#include	<sys/socket.h>
#include	<arpa/inet.h>
#include	<netinet/if_ether.h>
#include	<netinet/ip.h>
#include	<netinet/ip6.h>
#include	<netinet/ip_icmp.h>
#include	<netinet/icmp6.h>
#include	<netinet/tcp.h>
#include	<netinet/udp.h>
#include	<linux/if.h>
#include	<net/ethernet.h>
#include	<netpacket/packet.h>
#include	<pthread.h>
#include        <ctype.h>
#include        <fcntl.h>
#include        <openssl/bio.h>
#include        <openssl/err.h>
#include        <openssl/pem.h>
#include        <openssl/ssl.h>
#include        <openssl/opensslv.h>
#include        <openssl/x509.h>
#include        <openssl/x509_vfy.h>
#include	"init.h"
#include	"createArp.h"
#include	"murmur3.h"
#include	"base.h"
#include	"analysis.h"
#include	"rewrite.h"
#include        "checksum.h"
#include        "ssl_component.h"
#include        "dhcp.h"

#define DEV_SUPERVISOR "/dev/Supervisor"
#define VNIC_IFC "Supervisor"
#define NORTHBOUND_IFC "enp1s0" //NIC NAME for Ad Hoc Mode
#define XOR_KEY 0xAA             // XOR暗号化キー
#define BUFFSIZE 4096 //BUFFSIZE for a packet
#define RFLAG 0 //Flag for Rewriting Port
#define OPTION_SIZE 40

typedef struct {
  char* Device1;
  char* Device2;
}PARAM;
PARAM Name = { NORTHBOUND_IFC, VNIC_IFC };  //NIC NAME
DEVICE Device[4];
u_char DEVICE1_MAC[6];
u_char DEVICE2_MAC[6];
u_char BArray[6] = { 0xff,0xff,0xff,0xff,0xff,0xff };

int Endflag = 0;

pthread_t th1, th2, th3;

/*Debug Function*/
char* ip_ntoa(u_int32_t ip) {
  u_char* d = (u_char*)& ip;
  static char str[15];
  sprintf(str, "%d.%d.%d.%d", d[0], d[1], d[2], d[3]);
  return str;
}

char* ip_ntoa2(u_char* d) {
  static char str[15];
  sprintf(str, "%d.%d.%d.%d", d[0], d[1], d[2], d[3]);
  return str;
}

char* mac_ntoa(u_char* d) {
  static char str[18];
  sprintf(str, "%02x:%02x:%02x:%02x:%02x:%02x", d[0], d[1], d[2], d[3], d[4], d[5]);
  return str;
}
/*-------------*/

// 暗号化関数（XOR方式）
void xor_encrypt(unsigned char *data, int len) {
    for (int i = 0; i < len; i++) {
        data[i] ^= XOR_KEY;
    }
}

int Bridge() {
  int supervisor_fd, check, nready, i, size, optionLen, len;
  u_char* ptr;
  u_char buf[BUFFSIZE];//buffer for packet
  u_char tmpBuf[BUFFSIZE];//tmp buffer for modification
  u_char option[1500];
  struct ether_header* eh;
  struct ether_arp* arp;
  struct iphdr* iphdr;
  struct udphdr* udphdr;
  struct tcphdr* tcphdr;
  struct dhcp_static_part* dhcphdr;
  struct dhcp_options_request* dhcp_request;
  struct pollfd targets[2];//pollfd structure

  supervisor_fd = open(DEV_SUPERVISOR, O_RDWR);

  targets[0].fd = Device[0].soc;
  targets[0].events = POLLIN | POLLERR;
  targets[1].fd = Device[1].soc;
  targets[1].events = POLLIN | POLLERR;

  while (Endflag == 0) {
    switch (nready = poll(targets, 2, 100)) {
    case -1:
      if (errno != EINTR) {
	perror("poll");
      }
      break;
    case 0:
      break;
    default:
      for (i = 0; i < 2; i++) {
	if (targets[i].revents & (POLLIN | POLLERR)) {
	  if ((size = read(Device[i].soc, buf, sizeof(buf))) <= 0) {
	    perror("read_Dev1_or_Dev2");
	  }
	  else {
	    ptr = buf;
	    if (i == 0) {
	      //Communication at DEVICE1_NIC
	      //Ethernet II
	      eh = (struct ether_header*) ptr;
	      ptr += sizeof(struct ether_header);
	      optionLen = 0;

	      if (ntohs(eh->ether_type) == ETHERTYPE_ARP) {
		//ARP
		puts("read arp");
		arp = (struct ether_arp*)ptr;
		check = 0;
		//---Customize space for ARP---
		
		if (arp->arp_op == htons(ARPOP_REPLY)) {
		  //For wireless
		  //memcpy(arp->arp_tha, &DEVICE2_MAC, 6);
		  //check = 1;
		}
		else if (arp->arp_op == htons(ARPOP_REQUEST)) {
		}
		
		//-----------------------------
		ptr += sizeof(struct ether_arp);
	      }
	      else if (ntohs(eh->ether_type) == ETHERTYPE_IP) {
		//IPv4
		iphdr = (struct iphdr*) ptr;
		check = 0;
		/*add code*/

		/*ptr += sizeof(struct iphdr);
		optionLen = iphdr->ihl * 4 - sizeof(struct iphdr);
		memcpy(option, ptr, optionLen);
		ptr += optionLen;

		unsigned char encrypted_ip[4];
		memcpy(encrypted_ip, &iphdr->daddr, 4);
		xor_encrypt(encrypted_ip, 4);
		if(optionLen >= 4){
		  memcpy(option, encrypted_ip, 4);
		}

		iphdr->daddr = htonl(0xFFFFFFFF);

		iphdr->check = 0;
		iphdr->check = checksum2((u_char*)iphdr, sizeof(struct iphdr), option, optionLen);*/

		//---Customize Space for IPv4 header---
		if (iphdr->protocol == IPPROTO_ICMP) {
		  puts("Ping read");
		  
		  if(iphdr->ihl > 5){
		    int optionLength = (iphdr->ihl - 5) * 4;
		    memcpy(tmpBuf, ptr + sizeof(struct iphdr), optionLength);
		    int idx = 0;
		    while(idx < optionLength){
		      printf("%#x", tmpBuf[idx]);
		      idx = idx + 1;
		    }
		    printf("\n");
		    iphdr->ihl -= optionLength/4;
		    iphdr->tot_len = htons(ntohs(iphdr->tot_len) - optionLength);
		    size -= optionLength;
		    check = 1;
		  }
		  
		}
		//-----------------------------------
		ptr += sizeof(struct iphdr);
		optionLen = iphdr->ihl * 4 - sizeof(struct iphdr); //Max length of IP header = fixed length 20bytes + max option length 40 bytes = 60 bytes
		memcpy(&option, ptr, optionLen);
		ptr += optionLen;
		if (check) {
		  iphdr->check = 0;
		  iphdr->check = checksum2((u_char*)iphdr, sizeof(struct iphdr), option, optionLen);
		}
		if (iphdr->protocol == IPPROTO_UDP) {
		  //UDP
		  udphdr = (struct udphdr*) ptr;
		  check = 0;
		  //---Customize Space for UDP---
		  
		  //DHCP
		  if (udphdr->dest == htons(DHCP_CLIENT_PORT)) {
		    printf("DHCP_REPLY_PACKET\n");
		    dhcphdr = (struct dhcp_static_part*)(ptr + sizeof(struct udphdr));
		    memcpy(dhcphdr->client_haddr, &DEVICE2_MAC, 6);
		    check = 1;
		  }
		  
		  //-----------------------------------
		  if (check) {
		    len = ntohs(iphdr->tot_len) - iphdr->ihl * 4;
		    udphdr->check = 0;
		    udphdr->check = checkIPDATAchecksum(iphdr, ptr, len);
		  }
		}
		else if (iphdr->protocol == IPPROTO_TCP) {
		  //TCP
		  tcphdr = (struct tcphdr*) ptr;
		  check = 0;
		  //---Customize space for TCP data---
		  //check = 1;
		  //----------------------------------
		  
		  //If TCP data is rewritten
		  if (check) {
		    len = ntohs(iphdr->tot_len) - iphdr->ihl * 4;
		    tcphdr->check = 0;
		    tcphdr->check = checkIPDATAchecksum(iphdr, ptr, len);
		  }
		}
	      }
	      if ((size = write(supervisor_fd, buf, size)) <= 0) { //System write to outer raspi
		perror("write_Dev1");
	      }
	    }
	    else if (i == 1) {
	      //Communication at DEVICE2_NIC
	      //Ethernet II
	      eh = (struct ether_header*) ptr;
	      ptr += sizeof(struct ether_header);
	      optionLen = 0;
	      if (memcmp(eh->ether_shost, &DEVICE2_MAC, 6) != 0) {
		break;
	      }
	      //puts("vnic read");
	      /*
	      //For wireless
	      memcpy(eh->ether_shost, &DEVICE1_MAC, 6)
	      */
	      if (ntohs(eh->ether_type) == ETHERTYPE_ARP) {
		//ARP
		puts("vnic arp write");
		arp = (struct ether_arp*)ptr;
		check = 0;
		//---Customize space for ARP header---
		
		if (arp->arp_op == htons(ARPOP_REPLY)) {
		  //For wireless
		  //memcpy(arp->arp_sha, &DEVICE1_MAC, 6);
		  //check = 1;
		}
		else if (arp->arp_op == htons(ARPOP_REQUEST)) {
		  //For wireless
		  //memcpy(arp->arp_sha, &DEVICE1_MAC, 6);
		  //check = 1;
		}
		
		//------------------------------------
		ptr += sizeof(struct ether_arp);
	      }
	      else if (ntohs(eh->ether_type) == ETHERTYPE_IP) {
		//IPv4
		iphdr = (struct iphdr*) ptr;
		check = 0;
		/*add code*/
		ptr += sizeof(struct iphdr);
		optionLen = iphdr->ihl * 4 - sizeof(struct iphdr);
		memcpy(option, ptr, optionLen);
		ptr += optionLen;

		unsigned char encrypted_ip[4];
		memcpy(encrypted_ip, &iphdr->daddr, 4);
		xor_encrypt(encrypted_ip, 4);
		if(optionLen >= 4){
		  memcpy(option, encrypted_ip, 4);
		}

		iphdr->daddr = htonl(0xFFFFFFFF);

		iphdr->check = 0;
		iphdr->check = checksum2((u_char*)iphdr, sizeof(struct iphdr), option, optionLen);

		//---Customize Space for IP header---
		if (iphdr->protocol == IPPROTO_ICMP) {
		  puts("ping write!");
		  /*add code*/
		  /*unsigned char encrypted_ip[4];
		  memcpy(encrypted_ip, &iphdr->daddr, 4);
		  xor_encrypt(encrypted_ip, 4);*/
		  memset(option, 1, sizeof(option));
		  memset(option, encrypted_ip[4], 4);

		  memcpy(tmpBuf, ptr + sizeof(struct iphdr), size - sizeof(struct ether_header) - sizeof(struct iphdr));
		  memcpy(ptr + sizeof(struct iphdr), option, OPTION_SIZE);
		  memcpy(ptr + sizeof(struct iphdr) + OPTION_SIZE, tmpBuf, size - sizeof(struct ether_header) - sizeof(struct iphdr));
		  iphdr->ihl += OPTION_SIZE/4;
		  iphdr->tot_len = htons(ntohs(iphdr->tot_len) + OPTION_SIZE);
		  size += OPTION_SIZE;
		  check = 1;
		}
		//-----------------------------------
		ptr += sizeof(struct iphdr);
		optionLen = iphdr->ihl * 4 - sizeof(struct iphdr);
		memcpy(option, ptr, optionLen);
		ptr += optionLen;
		//If IP header is rewritten
		if (check) {
		  iphdr->check = 0;
		  iphdr->check = checksum2((u_char*)iphdr, sizeof(struct iphdr), option, optionLen);
		}
		if (iphdr->protocol == IPPROTO_UDP) {
		  //UDP
		  udphdr = (struct udphdr*) ptr;
		  check = 0;
		  //---Customize Space for UDP data---
		  
		  //DHCP
		  if (udphdr->dest == htons(DHCP_SERVER_PORT)) {
		    printf("DHCP Request Packet\n");
		    dhcphdr = (struct dhcp_static_part*)(ptr + sizeof(struct udphdr));
		    memcpy(dhcphdr->client_haddr, &DEVICE1_MAC, 6);
		    dhcp_request = (struct dhcp_options_request*)(ptr + sizeof(struct udphdr) + sizeof(struct dhcp_static_part));
		    memcpy(dhcp_request->client_mac, &DEVICE1_MAC, 6);
		    check = 1;
		  }
		  
		  //------------------------------------
		  
		  //If UDP data is rewritten
		  if (check) {
		    len = ntohs(iphdr->tot_len) - iphdr->ihl * 4;
		    udphdr->check = 0;
		    udphdr->check = checkIPDATAchecksum(iphdr, ptr, len);
		  }
		}
		else if (iphdr->protocol == IPPROTO_TCP) {
		  //TCP
		  tcphdr = (struct tcphdr*) ptr;
		  check = 0;
		  //---Customize space for TCP data---
		  //check = 1;
		  //----------------------------------
		  //If TCP data is rewritten
		  if (check) {
		    len = ntohs(iphdr->tot_len) - iphdr->ihl * 4;
		    tcphdr->check = 0;
		    tcphdr->check = checkIPDATAchecksum(iphdr, ptr, len);
		  }
		}
	      }
	      if ((size = write(Device[0].soc, buf, size)) <= 0) { //system write to inter raspi
		perror("write_Dev2");
	      }
	      //puts("vnic_write");
	    }
	  }
	}
      }
      break;
    }
  }
  return(0);
}

void EndSignal(int sig) {
  Endflag = 1;
  printf("bridge end\n");
  close(Device[0].soc);
  close(Device[1].soc);
  close(Device[2].soc);
  pthread_kill(th1, 2);
  pthread_kill(th2, 2);
}

/*
//Thread Definition
void *BRIDGE(void *args){
  printf("threads1 : BRIDGE start\n");
  Bridge();
  return NULL;
}

void *SUPERVISOR(void *args){
  printf("threads2 : SUPERVISOR start\n");
  Supervisor();
  return NULL;
}
*/

int main(int argc, char* argv[], char* envp[]) {

  getDevMACaddr(Name.Device1, DEVICE1_MAC);
  getDevMACaddr(Name.Device2, DEVICE2_MAC);
  
  if ((Device[0].soc = InitRawSocket(Name.Device1, 1, 0)) == -1) {
    printf("InitRawSocket:error :%s\n", Name.Device1);
    return (-1);
  }
  printf("%s.socket is OK\n", Name.Device1);
  if ((Device[1].soc = InitRawSocket(Name.Device2, 1, 0)) == -1) {
    printf("InitRawSocket:error :%s\n", Name.Device2);
    return (-1);
  }
  printf("%s.socket is OK\n", Name.Device2);
  
  printf("%s.MAC[0] is %02x:%02x:%02x:%02x:%02x:%02x\n", Name.Device1,
	 DEVICE1_MAC[0],
	 DEVICE1_MAC[1],
	 DEVICE1_MAC[2],
	 DEVICE1_MAC[3],
	 DEVICE1_MAC[4],
	 DEVICE1_MAC[5]
	 );
  printf("%s.MAC[0] is %02x:%02x:%02x:%02x:%02x:%02x\n", Name.Device2,
	 DEVICE2_MAC[0],
	 DEVICE2_MAC[1],
	 DEVICE2_MAC[2],
	 DEVICE2_MAC[3],
	 DEVICE2_MAC[4],
	 DEVICE2_MAC[5]
	 );
  
  //InitializeSSL();
  DisableIpForward();
  
  /*
  //Thread Variables
  int status;
  
  //Thread Initialization
  if((status = pthread_create(&th1,NULL,BRIDGE,NULL)) != 0){ //succeed = 0
  printf("threads1 : BRIDGE error");
  }

  if((status = pthread_create(&th2,NULL,SUPERVISOR,NULL)) != 0){ //succeed = 0
  printf("threads2 : SUPERVISOR error");
  }
  
  //Thread Run
  pthread_join(th1,NULL);
  pthread_join(th2,NULL);
  */
  
  Bridge();
  
  signal(SIGINT, EndSignal);
  signal(SIGTERM, EndSignal);
  signal(SIGQUIT, EndSignal);
  
  signal(SIGPIPE, SIG_IGN);
  signal(SIGTTIN, SIG_IGN);
  signal(SIGTTOU, SIG_IGN);
  
  return (0);
}
