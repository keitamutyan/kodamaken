#pragma once
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include "base.h"
#include "init.h"
#include "createArp.h"

extern HARDWARE hw;
extern DEVICE Device[2];

int AnalyzePacket(int deviceNo, u_char *data, int size) {
	int lest;
	lest = size;

	if (lest < sizeof(struct ether_header)) {
		printf("[%d]: lest (%d)<sizeof(struct ether_header )\n", deviceNo, lest);
		return (-1);
	}
	return (0);
}

/*int HeaderLen(int deviceNo, u_char *data, int size) {
	u_char *ptr;
	//データの先頭ポインタ格納用
	int lest, ipoptionLen;
	データサイズ、IPオプション長格納用
	int arp_header = 28;
	//ARPヘッダサイズ
	struct ether_header *eh;
	//Ethernet構造体
	struct ether_arp *arp;
	//ARP構造体

	ptr = data;
	lest = size;
	if (lest < sizeof(struct ether_header)) {
		printf("[%d]: lest (%d)<sizeof(struct ether_header )\n", deviceNo, lest);
		return (-1);
	}
	eh = (struct ether_header *) ptr;

	ptr += sizeof(struct ether_header);
	lest -= sizeof(struct ether_header);

	if (ntohs(eh->ether_type) == ETHERTYPE_IP) {
		struct iphdr *iphdr;
		iphdr = (struct iphdr *) ptr;
		ptr += sizeof(struct iphdr);
		lest -= sizeof(struct iphdr);
		ipoptionLen = iphdr->ihl * 4 - sizeof(struct iphdr);
		if (ipoptionLen >= 0) {
			if (ipoptionLen >= 1500) {
				fprintf(stderr, "IP optionLen (%d):too big\n", ipoptionLen);
				return (-1);
			}
			return (sizeof(struct ether_header) + (iphdr->ihl * 4));
		}
	}
	//printf("test:A");
	if (ntohs(eh->ether_type) == ETHERTYPE_ARP) {
		arp = (struct ether_arp *) ptr;
		char sMACaddr[18]; //送信元MACアドレス格納用
		MACaddr_ntoa(eh->ether_shost, sMACaddr, sizeof(sMACaddr));
		if (strcmp(sMACaddr, "66:66:66:66:66:66") == 0) {
			printf("update\n");
			unsigned int tmp = arp->arp_tha[0];
			unsigned int rand = tmp << 24;
			tmp = arp->arp_tha[1];
			rand = (tmp << 16) | rand;
			tmp = arp->arp_tha[2];
			rand = (tmp << 8) | rand;
			tmp = arp->arp_tha[3];
			rand = (rand) | tmp;
			murmur3_48(hw.current, hw.original, strlen(hw.original), rand);
			printf("New ID: %02x%02x%02x%02x%02x%02x\n",hw.current[0],hw.current[1],hw.current[2],hw.current[3],hw.current[4],hw.current[5]);
			create_arp(Device[0].soc, address, hw.current);
		}

		if (strcmp(sMACaddr, hwaddr) == 0) {
			int i;
			for (i = 0; i < 6; i++) {
				arp->arp_sha[i] = hw.current[i];
				eh->ether_shost[i] = u_hwaddr[i];
			}
		}
		return (arp_header + sizeof(struct ether_header));
	}
	return (sizeof(struct ether_header));
}
*/

int DataLen(int deviceNo, u_char *data, int size) {
	u_char *ptr;
	/*データの先頭ポインタ格納用*/
	int ipoptionLen, lest = 0;
	/*IPオプションの長さ、データサイズ格納用*/
	struct ether_header *eh;
	/*Ethernet構造体*/
	ptr = data;
	lest = size;
	if (lest < sizeof(struct ether_header)) {
		printf("[%d]:lest(%d)<sizeof(struct ether_header )\n", deviceNo, lest);
		return (-1);
	}
	eh = (struct ether_header *) ptr;
	ptr += sizeof(struct ether_header);
	lest -= sizeof(struct ether_header);

	if (ntohs(eh->ether_type) == ETHERTYPE_IP) {
		struct iphdr *iphdr; /*IPヘッダ構造体*/
		iphdr = (struct iphdr *) ptr;
		ptr += sizeof(struct iphdr);
		lest -= sizeof(struct iphdr);
		ipoptionLen = iphdr->ihl * 4 - sizeof(struct iphdr);
		if (ipoptionLen > 0) {
			if (ipoptionLen >= 1500) {
				fprintf(stderr, "IP optionLen (%d):too big\n", ipoptionLen);
				return (-1);
			}
			ptr += ipoptionLen;
			lest -= ipoptionLen;
			return (lest);
		}
		if (ipoptionLen == 0) {
			return (lest);
		}
	}
	return (0);
}
