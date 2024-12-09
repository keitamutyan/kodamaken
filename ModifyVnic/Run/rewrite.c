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

extern HARDWARE hw;

int Hash(char *key) {
	int hashsize = 127;
	int len, ret;

	len = strlen(key);
	ret = key[0];
	ret += key[len - 1];
	ret += key[(len - 1) / 2];

	return (ret % hashsize);
}
u_char pfun(u_char x, int u) {
	u_char y;
	y = x + (u_char) u;
	return (y);
}

u_char nfun(u_char x, int u) {
	u_char y;
	y = x - (u_char) u;
	return (y);
}

/*void rewritefun(u_char *data, int deviceNo, int size, int datasize,
		int headerlen) {
	int i, hashval, lest;
	struct ether_header *eh;
	u_char *ptr;
	char sMACaddr[18];
	char dMACaddr[18];
	char tmp[7];
	char buf[18];

	ptr = data;
	lest = size;

	if (lest < sizeof(struct ether_header)) {
		printf("[%d]: lest (%d)<sizeof(struct ether_header )\n", deviceNo, lest);
		exit(0);
	}

	eh = (struct ether_header *) ptr;
	ptr += sizeof(struct ether_header);
	lest -= sizeof(struct ether_header);
	for (i = 0; i < 7; i++) {
		tmp[i] = hw.current[i];
		if (i == 6) {
			tmp[i] = '\0';
		}
	}
	MACaddr_ntoa(eh->ether_shost, sMACaddr, sizeof(sMACaddr));
	MACaddr_ntoa(eh->ether_dhost, dMACaddr, sizeof(dMACaddr));
	MACaddr_ntoa(hw.current, buf, sizeof(buf));
	if (deviceNo == 0) {
		hashval = Hash(buf);
		for (i = headerlen; i < (headerlen + datasize); i++) {
			data[i] = nfun(data[i], hashval);
		}
		if (strcmp(dMACaddr, buf) == 0) {
			eh->ether_dhost[0] = u_hwaddr[0];
			eh->ether_dhost[1] = u_hwaddr[1];
			eh->ether_dhost[2] = u_hwaddr[2];
			eh->ether_dhost[3] = u_hwaddr[3];
			eh->ether_dhost[4] = u_hwaddr[4];
			eh->ether_dhost[5] = u_hwaddr[5];
		}

	} else if (deviceNo == 1) {
		if (strcmp(sMACaddr, hwaddr) == 0) {
			for (i = 0; i < 6; i++) {
				eh->ether_shost[i] = tmp[i];
			}
		}
		hashval = Hash(buf);
		for (i = headerlen; i < (headerlen + datasize); i++) {
			data[i] = pfun(data[i], hashval);
		}
	}
}
*/
