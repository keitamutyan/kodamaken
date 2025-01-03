#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
// #include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/hdreg.h>
#include <stdio.h>
#include <netinet/in.h>
#include <sys/utsname.h>
#include "murmur3.h"

void getDevMACaddr(char *DevName, u_char *MACaddr){
  int fd;
  struct ifreq ifr;

  fd = socket(AF_INET, SOCK_DGRAM, 0);

  ifr.ifr_addr.sa_family = AF_INET;
  strncpy(ifr.ifr_name, DevName, IFNAMSIZ-1);
  
  ioctl(fd, SIOCGIFHWADDR, &ifr);
  memcpy(MACaddr, &ifr.ifr_hwaddr.sa_data, 6);

  close(fd);
}

int InitRawSocket(char *device, int promiscFlag, int ipOnly) {
	struct ifreq ifreq; /*ifreq構造体*/
	struct sockaddr_ll sa;
	/*sockaddr_ll構造体*/
	int soc;
	/*ソケットディスクリプタ格納用*/

	//socket関数の構成　socket(domain, type, protocol)
	//PF_PACKETには数字の17が入っている 関連しているヘッダー
	//
	if (ipOnly) {
		if ((soc = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0) {
			fprintf(stderr, "socket%s\n", strerror(errno));
			return (-1);
		}
	} else {
		if ((soc = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
			fprintf(stderr, "socket%s\n", strerror(errno));
			return (-1);
		}
	}
	memset(&ifreq, 0, sizeof(struct ifreq)); //ifreqを対象にifreqのもつサイズ分初期化している
	strncpy(ifreq.ifr_name, device, sizeof(ifreq.ifr_name) - 1);　//-1をしている理由C言語では文字列は通常、**最後にヌル文字（'\0'）**で終端される必要があります。 
	if (ioctl(soc, SIOCGIFINDEX, &ifreq) < 0) {						// ヌル終端文字を確保しないと、文字列として正しく扱えない場合があります。
		fprintf(stderr, " ioctl　 %s\n", strerror(errno));
		close(soc);
		return (-1);
	}
	sa.sll_family = PF_PACKET;
	if (ipOnly) {
		sa.sll_protocol = htons(ETH_P_IP);
	} else {
		sa.sll_protocol = htons(ETH_P_ALL);
	}
	sa.sll_ifindex = ifreq.ifr_ifindex;
	if (bind(soc, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
		fprintf(stderr, " bind　 %s\n", strerror(errno));
		close(soc);
		return (-1);
	}
	if (promiscFlag) {
		if (ioctl(soc, SIOCGIFFLAGS, &ifreq) < 0) {
			fprintf(stderr, " ioctl　 %s\n", strerror(errno));
			close(soc);
			return (-1);
		}
		ifreq.ifr_flags = ifreq.ifr_flags | IFF_PROMISC;
		if (ioctl(soc, SIOCSIFFLAGS, &ifreq) < 0) {
			fprintf(stderr, " ioctl　 %s\n", strerror(errno));
			close(soc);
			return (-1);
		}
	}
	return (soc);
}

char *MACaddr_ntoa(u_char *hwaddr, char *buf, socklen_t size) {
	snprintf(buf, size, "%02x:%02x:%02x:%02x:%02x:%02x", hwaddr[0], hwaddr[1],
			hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);
	return (buf);
}

unsigned char *getSerialNum(char* source, unsigned char *serial) {
	int fd, err = 0; /*ファイルディスクリプタ格納用、エラー番号格納用*/
	struct hd_driveid id; /*hd_driveid構造体*/
	struct utsname      uname_buff; /*utsname構造体*/
	unsigned char buf[100]; /*一時バッファ*/

	fd = open(source, O_RDONLY | O_NONBLOCK);
	if (fd != -1) {
		if (ioctl(fd, HDIO_GET_IDENTITY, &id) != -1) {
			int i;
			for (i = 0; i < 20; i++) {
				serial[i] = id.serial_no[i];
			}
		} else {
			err = errno;
			printf("0\n");
			return 0;
		}
	} else {
		err = errno;
		perror(source);
	}

	  if (uname(&uname_buff) == 0) {
		  sprintf(buf,"%s%s",serial,uname_buff.version);
	 }else {
	    perror("main");
	  }
	  murmur3_48(serial, buf, strlen(buf), 0);
	  return serial;

}

int get_ifhw(char *devname, char *buf, socklen_t size, unsigned char *u_buf) {
	int fd; /*ファイルディスクリプタ格納用*/
	struct ifreq ifr; /*ifreq構造体*/
	int i;
	/*ループ用*/

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, devname, IFNAMSIZ - 1);
	ioctl(fd, SIOCGIFHWADDR, &ifr);

	for (i = 0; i < 6; i++) {
		u_buf[i] = ifr.ifr_hwaddr.sa_data[i];

	}
	snprintf(buf, size, "%02x:%02x:%02x:%02x:%02x:%02x",
			(unsigned char) ifr.ifr_hwaddr.sa_data[0],
			(unsigned char) ifr.ifr_hwaddr.sa_data[1],
			(unsigned char) ifr.ifr_hwaddr.sa_data[2],
			(unsigned char) ifr.ifr_hwaddr.sa_data[3],
			(unsigned char) ifr.ifr_hwaddr.sa_data[4],
			(unsigned char) ifr.ifr_hwaddr.sa_data[5]);

	return 0;
}
int get_ifip(char *devname, unsigned char *address) {
	int fd;
	struct ifreq ifr;
	struct sockaddr_in *sin;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, devname, IFNAMSIZ - 1);
	ioctl(fd, SIOCGIFADDR, &ifr);

	sin = (struct sockaddr_in *) &ifr.ifr_addr;
	memcpy(address, (unsigned char *) &sin->sin_addr.s_addr,
			sizeof(unsigned char) * 4);
	return 0;
}

int DisableIpForward() {
	FILE *fp;

	if ((fp = fopen("/proc/sys/net/ipv4/ip_forward", "w")) == NULL) {
		printf("cannot write /proc/sys/net/ipv4/ip_forward\n");
		return (-1);
	}

	fputs("0", fp);
	fclose(fp);

	return (0);
}

