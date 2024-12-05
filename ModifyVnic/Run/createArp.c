#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in_systm.h>
#include <netinet/if_ether.h>
#define MAXSIZE 8192
#define CMAX    256
enum {
	CMD_NAME, IFNAME, DST_IP, MAC_ADDR, OPTION
};
enum {
	NORMAL, REPLY, REQUEST
};
void make_ethernet(struct ether_header *eth, unsigned char *ether_dhost,
                   unsigned char *ether_shost, u_int16_t ether_type);
void make_arp(struct ether_arp *arp, int op, unsigned char *arp_sha,
              unsigned char *arp_spa, unsigned char *arp_tha,
              unsigned char *arp_tpa);
void create_arp(int soc, unsigned char *address, unsigned char *serial) {

	u_char mac_addr[6];
	/*MACアドレス格納用*/
	int flag; /*ARPパケットタイプ指定用*/
	int len;
	/*ARPパケットサイズ格納用*/
	u_char saddr[6];
	/*送信元MACアドレス格納用*/
	int i; /*ループ用*/

	struct ether_header *eth; /*Ethernetヘッダ構造体*/
	char recv_buff[MAXSIZE]; /*受信バッファ*/
	char send_buff[MAXSIZE]; /*送信バッファ */
	char *rp; /*受信ヘッダの先頭ポインタ*/
	char *rp0; /*受信パケットの先頭ポインタ*/
	char *sp; /*送信ヘッダの先頭ポインタ*/
	struct ether_arp *arp; /*ARPパケット構造体*/
	static u_char one[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	/* EthernetブロードキャストMACアドレス */
	flag = REQUEST;
	int x = 0;
	for (x = 0; x < 6; x++) {
		saddr[x] = 0x77;
	}

	for (i = 0; i < 6; i++) {
		mac_addr[i] = (char) serial[i];
	}

	rp = rp0 = recv_buff;
	eth = (struct ether_header *) rp;
	rp = rp + sizeof(struct ether_header);
	arp = (struct ether_arp *) rp;
	sp = send_buff + sizeof(struct ether_header);
	switch (flag) {
	case REQUEST:
		make_arp((struct ether_arp *) sp, ARPOP_REQUEST, mac_addr, address,
				saddr, address);
		make_ethernet((struct ether_header *) send_buff, one, mac_addr,
				ETHERTYPE_ARP);
		break;
	default:
		break;
	}
	len = sizeof(struct ether_header) + sizeof(struct ether_arp);
	if (write(soc, send_buff, len) < 0) {
		perror("write");
		exit(EXIT_FAILURE);
	}
}

void make_ethernet(struct ether_header *eth, unsigned char *ether_dhost,
		unsigned char *ether_shost, u_int16_t ether_type) {
	memcpy(eth->ether_dhost, ether_dhost, 6);
	memcpy(eth->ether_shost, ether_shost, 6);
	eth->ether_type = htons(ether_type);
}

void make_arp(struct ether_arp *arp, int op, unsigned char *arp_sha,
		unsigned char *arp_spa, unsigned char *arp_tha, unsigned char *arp_tpa) {
	arp->arp_hrd = htons(1);
	arp->arp_pro = htons(ETHERTYPE_IP);
	arp->arp_hln = 6;
	arp->arp_pln = 4;
	arp->arp_op = htons(op);
	memcpy(arp->arp_sha, arp_sha, 6);
	memcpy(arp->arp_spa, arp_spa, 4);
	memcpy(arp->arp_tha, arp_tha, 6);
	memcpy(arp->arp_tpa, arp_tpa, 4);
}
