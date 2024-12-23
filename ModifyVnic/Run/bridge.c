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
#include "createArp.h"
#include "murmur3.h"
#include "base.h"
#include "init.h"
#include "rewrite.h"
#include "analysis.h"
#define  DEV	"/dev/vnic"
#include <fcntl.h>
int fd;

DEVICE_NAME Name = { "enp0s31f6", "vnic" };
DEVICE Device[2];

HARDWARE hw;
unsigned char oriserial[20];
unsigned char serial[20];
unsigned char original[20];
char s_original[18];
int EndFlag = 0;

int Bridge() {
  char sMAC[18];
  char dMAC[18];
  fd=open(DEV,O_RDWR);
  u_char *ptr;
  struct ether_header *eh;
  struct pollfd fds[2];
  /*pollfd構造体*/
  int i, nready, size;
  /*ループ用、イベント格納用、読込バイト数格納用*/
  u_char buf[2048];
  /*データ格納用*/
  int headerlen, datasize;
  /*ヘッダ長、データ長格納用*/
  fds[0].fd = Device[0].soc;
  fds[0].events = POLLIN | POLLERR;
  fds[1].fd = Device[1].soc;
  fds[1].events = POLLIN | POLLERR;

  while (EndFlag == 0) {
    switch (nready = poll(fds, 2, 100)) {
    case -1:
      if (errno != EINTR) {
	perror("poll");
      }
      break;
    case 0:
      break;
    default:
      for (i = 0; i < 2; i++) {
	if (fds[i].revents & (POLLIN | POLLERR)) {
	  if ((size = read(Device[i].soc, buf, sizeof(buf))) <= 0) {
	    perror("read");
	  } else {
	    ptr = buf;
	    eh = (struct ether_header *) ptr;
	    datasize = DataLen(i, buf, size);
	    headerlen = HeaderLen(i, buf, size);
	    rewritefun(buf, i, size, datasize, headerlen);
	    MACaddr_ntoa(eh->ether_shost,sMAC,sizeof(sMAC));
	    MACaddr_ntoa(eh->ether_dhost,dMAC,sizeof(dMAC));
	    if ((AnalyzePacket(i, buf, size)) != -1) {
	      if(i==0){
		if ((size = write(fd, buf, size))<= 0) {
		  perror("write");
		}
	      }else{
		//printf("shost==%s\n", sMAC);
		//printf("dhost==%s\n", dMAC);
		//printf("test");
		if(strcmp(dMAC,hwaddr)==0){
		  //printf("dMAC hwaddr onaji\n");
		}else{
		  if ((size = write(Device[(!i)].soc, buf, size))<= 0) {
		    perror("write");
		  }
		}
	      }
	    }
	  }
	}
      }
      break;
    }
  }
  return (0);
}

void EndSignal(int sig) {
  EndFlag = 1;
}

int main(int argc, char *argv[], char *envp[]) {

  int i = 0;
  /*ループ用*/
  oriserial[0]=0;
  getSerialNum("/dev/sda", oriserial);
  if(oriserial[0]==0){
    getSerialNum("/dev/sdb", oriserial);
  }
  memcpy(serial,oriserial,sizeof(serial));
  printf("My hardware ID is:%02x%02x%02x%02x%02x%02x\n",serial[0],serial[1],serial[2],serial[3],serial[4],serial[5]);
  for (i = 0; i < sizeof(hw.original) / sizeof(hw.original[0]); i++) {
    if (i == sizeof(hw.original) / sizeof(hw.original[0]) - 1) {
      hw.original[i] = '\0';
      hw.current[i] = '\0';
    } else {
      hw.original[i] = serial[i];
      hw.current[i] = serial[i];
    }
  }
  get_ifhw("vnic", hwaddr, sizeof(hwaddr), u_hwaddr);
  get_ifip("vnic", address);

  if ((Device[0].soc = InitRawSocket(Name.Device1, 1, 0)) == -1) {
    printf("InitRawSocket:error :%s\n", Name.Device1);
    return (-1);
  }
  printf("%s OK\n", Name.Device1);

  if ((Device[1].soc = InitRawSocket(Name.Device2, 1, 0)) == -1) {
    printf("InitRawSocket:error :%s\n", Name.Device2);
    return (-1);
  }
  printf("%s OK\n", Name.Device2);
  DisableIpForward();

  signal(SIGINT, EndSignal);
  signal(SIGTERM, EndSignal);
  signal(SIGQUIT, EndSignal);

  signal(SIGPIPE, SIG_IGN);
  signal(SIGTTIN, SIG_IGN);
  signal(SIGTTOU, SIG_IGN);

  printf("bridge start\n");
  Bridge();
  printf("bridge end\n");

  close(Device[0].soc);
  close(Device[1].soc);

  return (0);
}
