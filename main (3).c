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
#define NORTHBOUND_IFC "enp0s31f6" //NIC NAME for Ad Hoc Mode
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

void PrintKun(int size, const u_char *buf) {
	for (int j = 0; j < size; j++) {
		printf("%02x ", buf[j]); // 各バイトを16進数で出力
		if((j+1) % 8 == 0){
			printf("  ");
		}
		if((j+1) % 16 == 0){
			printf("\n");
		}
		if(j == (size - 1)){
			printf("\n");
		}
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

	// [/dev]ディレクトリは、ハードウェアデバイスやカーネルモジュールに
	// アクセスするためのデバイスファイルが配置されている。
	// [O_RDWR]を指定して読み書き込み可能なファイルディスクプリタを開き、デバイスとやり取りを行う。
	supervisor_fd = open(DEV_SUPERVISOR, O_RDWR);

	// 各NICとbind()させたソケットのファイルディスクプリタを.fdに設定
	targets[0].fd = Device[0].soc;
	// 監視したいイベントを追加
	// [POLLIN]：読み取り可能なデータが到着した時
	// [POLLERR]：何らかのpollエラーが発生した時
	targets[0].events = POLLIN | POLLERR;
	targets[1].fd = Device[1].soc;
	targets[1].events = POLLIN | POLLERR;

	// [一周する条件]
	// ・pollで監視対象に設定したファイルディスクプリタにイベントが発生するか、0.1秒経過すること。
	while (Endflag == 0) {
		// pollは複数のファイルディスクリプタ（ファイル記述子）を監視／制御する
		// [戻り値]：-1=エラー、0=タイムアウト、それ以外=イベント発生したファイルディスクプリタの数 
		switch (nready = poll(targets, 2, 100)) {
			// poll()がシグナルを受けて中断を行い-1を出力する
			case -1:
				// ctrl+cなど(=EINTR)以外の場合はperrorが行われる
				if (errno != EINTR) {
					perror("poll");
				}
				break;
			case 0:
				break;
			default:
				// 2つのNICのどちらでpollが起きたか調べるため[i < 2]
				for (i = 0; i < 2; i++) {
					// 設定した2つのイベント(両方orどちらか)が発生したのか、それ以外かをandのビット演算で確認
					// 例)revents & POLLIN  // 0000 1001 & 0000 0001 = 0000 0001 (POLLINが有効)
					if (targets[i].revents & (POLLIN | POLLERR)) {
						// 「Device[i].soc」(fd)に書かれているソケット情報を基に、
						// カーネルが管理している受信バッファを[sizeof(buf)]分受け取り、それをbufに書き込んでいる。
						// sizeには戻り値として、読み取ったバイト数が入る。（何も読み取れない際は0）
						if ((size = read(Device[i].soc, buf, sizeof(buf))) <= 0) {
							perror("read_Dev1_or_Dev2");
						} else {
							// bufの先頭アドレスをptrへ
							ptr = buf;
							printf("[生パケット] : bufの中身\n");
							PrintKun(size, buf);
							if (i == 0) {	// 1つ目なので[enp0s31f6]
								//Communication at DEVICE1_NIC
								//Ethernet II

								// ptr(*buf)をether_header*型にキャストする。
								// 結果、ehはptrを基に、[struct ether_header]としてデータを解釈。
								// つまり見ているデータは同じ（ether_headerというフィルター越しに見てる感じ）。
								// (バイト)
								// 0  - 5	宛先MACアドレス 	[ether_dhost]
								// 6  - 11	送信元MACアドレス 	[ether_shost]
								// 12 - 13	プロトコルタイプ	[ether_type]
								// 14...	ペイロード
								eh = (struct ether_header*) ptr;
								// ptrの指しているアドレスを、イーサネットヘッダ分スキップ->する
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
								// ntohs()でether_typeの値を変換し、IPv4プロトコルと合致するか見ている
								// ntohs()はネットワークバイトオーダー（ビッグエンディアン）を、ホストバイトオーダー（システム依存）に変換する。
								// ehが構造体ポインタであるため「->」を使う。実体の場合は「.」を使う。
								else if (ntohs(eh->ether_type) == ETHERTYPE_IP) {
									//IPv4
									// イーサネットヘッダ分スキップされたポインタをキャストし、
									// iphdr構造体として現在のアドレスから始まるデータを解釈する構造体ポインタを作成。
									iphdr = (struct iphdr*) ptr;
									check = 0;
									//---Customize Space for IPv4 header---
									// [ICMP]：通信状態の確認をするために使われるプロトコル
									if (iphdr->protocol == IPPROTO_ICMP) {
										puts("Ping read");
										
										// ヘッダーの長さが最小値異常だった場合
										if(iphdr->ihl > 5){
											// optionの長さを計算し格納
											int optionLength = (iphdr->ihl - 5) * 4;
											// tmpBufにptr(ipヘッダ分スキップ)からoptionLengthバイト分コピーする
											memcpy(tmpBuf, ptr + sizeof(struct iphdr), optionLength);
											int idx = 0;
											// 恐らくoption分を標準出力
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
									// ipヘッダー分ポインタをスキップ
									ptr += sizeof(struct iphdr);
									// ipヘッダのオプションサイズを計算し格納（単位バイト）
									optionLen = iphdr->ihl * 4 - sizeof(struct iphdr); //Max length of IP header = fixed length 20bytes + max option length 40 bytes = 60 bytes
									// option内にptrを起点にoptionLenバイト分コピーする
									memcpy(&option, ptr, optionLen);
									// ipヘッダのoption領域分ポインタを移動（ポインタ先をペイロード内に移動）
									ptr += optionLen;
									if (check) {	// checkが0以外の時
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
									} else if (iphdr->protocol == IPPROTO_TCP) {
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
								// ptrの指しているアドレスがイーサネットヘッダ分スキップされる
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
								} else if (ntohs(eh->ether_type) == ETHERTYPE_IP) {
									//IPv4
									iphdr = (struct iphdr*) ptr;
									check = 0;
									//---Customize Space for IP header---
									if (iphdr->protocol == IPPROTO_ICMP) {
										//puts("ping write!");
										//puts(iphdr->saddr);
										//printf(ntohl(iphdr->saddr));
										if (iphdr->saddr == 1){}
										printf("Source IP : %u\n", ntohl(iphdr->saddr));
										/*
										memset(option, 1, sizeof(option));
										memcpy(tmpBuf, ptr + sizeof(struct iphdr), size - sizeof(struct ether_header) - sizeof(struct iphdr));
										memcpy(ptr + sizeof(struct iphdr), option, OPTION_SIZE);
										memcpy(ptr + sizeof(struct iphdr) + OPTION_SIZE, tmpBuf, size - sizeof(struct ether_header) - sizeof(struct iphdr));
										iphdr->ihl += OPTION_SIZE/4;
										iphdr->tot_len = htons(ntohs(iphdr->tot_len) + OPTION_SIZE);
										size += OPTION_SIZE;
										check = 1;
										*/

										// optionに対して、sizeof(option)分１で埋める。
										// memset(option, 1, sizeof(option));
										memset(option, 1, sizeof(option));

										// tmpBufに対して、ipパケットのペイロード部分（ptrをipヘッダ分スキップ）の先頭アドレスから、
										// パケットの全体サイズ - (イーサネットヘッダ + ipヘッダ) = 恐らくipパケットのペイロードサイズ(バイト)分コピーする。
										// 要は、tmpBufにはipパケットのペイロード部分がコピーされたものと思われる。
										memcpy(tmpBuf, ptr + sizeof(struct iphdr), size - sizeof(struct ether_header) - sizeof(struct iphdr));

										// [ptr + sizeof(struct iphdr)]：ipパケットのペイロード内の先頭アドレスに対して
										// option(1で埋まっている)をOPTION_SIZE分コピーする。
										// つまりすでに存在しているipヘッダの後ろにoption領域を追加した処理と考えられる。
										memcpy(ptr + sizeof(struct iphdr), option, OPTION_SIZE);

										// [ptr + sizeof(struct iphdr) + OPTION_SIZE]：ipヘッダ領域+前処理で追加したoption領域分スキップしたアドレスに対して
										// tmpBuf内から[全パケットサイズ-(イーサネットヘッダ+ipヘッダ)]をコピーする。
										// つまりipヘッダに新規追加したoption領域の後ろ部分に、もとあったペイロード部分を配置したと思われる。
										memcpy(ptr + sizeof(struct iphdr) + OPTION_SIZE, tmpBuf, size - sizeof(struct ether_header) - sizeof(struct iphdr));

										// optionサイズ分ihl(ヘッダーサイズ)を増加させる
										iphdr->ihl += OPTION_SIZE/4;

										// option領域の追加に伴うパケットサイズの増加
										iphdr->tot_len = htons(ntohs(iphdr->tot_len) + OPTION_SIZE);

										// 受信パケットの全体サイズを格納している[size]にoption分を追加
										size += OPTION_SIZE;

										// option操作フラグを立てる
										check = 1;
										printf("[ping] : 変更時のbufの中身\n");
										PrintKun(size, buf);
									}
									//-----------------------------------
									ptr += sizeof(struct iphdr);
									optionLen = iphdr->ihl * 4 - sizeof(struct iphdr);
									memcpy(option, ptr, optionLen);
									ptr += optionLen;
									printf("optionサイズ : %d\n", optionLen);
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

										if (ntohl(iphdr->saddr) ==3232235521){
											memset(option, 9, sizeof(option));
											// optionのTypeとLengthを入れる
											// [Type]
											// option[0] = 0b10001001;
											// [Length]
											// option[1] = 40;
											memcpy(tmpBuf, ptr, size - sizeof(struct ether_header) - sizeof(struct iphdr));
											printf("[UDP] : 退避させたUDPペイロードを確認\n");
											PrintKun(size+OPTION_SIZE, tmpBuf);

											memcpy(ptr, option, OPTION_SIZE);
											printf("[UDP] : optionを追加\n");
											PrintKun(size+OPTION_SIZE, buf);

											memcpy(ptr + OPTION_SIZE, tmpBuf, size - sizeof(struct ether_header) - sizeof(struct iphdr));
											printf("[UDP] : ペイロードを後方に追加\n");
											PrintKun((size+OPTION_SIZE), buf);

											iphdr->ihl += OPTION_SIZE/4;
											iphdr->tot_len = htons(ntohs(iphdr->tot_len) + OPTION_SIZE);
											size += OPTION_SIZE;
											check = 1;
										}

										ptr += sizeof(struct iphdr);
										optionLen = iphdr->ihl * 4 - sizeof(struct iphdr);
										memcpy(option, ptr, optionLen);
										ptr += optionLen;
										printf("optionサイズ : %d\n", optionLen);
										//If IP header is rewritten
										if (check) {
											iphdr->check = 0;
											iphdr->check = checksum2((u_char*)iphdr, sizeof(struct iphdr), option, optionLen);
										}
										
										//------------------------------------
										
										//If UDP data is rewritten
										// if (check) {
										// 	len = ntohs(iphdr->tot_len) - iphdr->ihl * 4;
										// 	udphdr->check = 0;
										// 	udphdr->check = checkIPDATAchecksum(iphdr, ptr, len);
										// }
									} else if (iphdr->protocol == IPPROTO_TCP) {
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
							printf("[最終パケット] : bufの中身\n");
							PrintKun(size, buf);
							printf("\n");
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

	// 物理NIC・VNICのMACアドレスを獲得
	getDevMACaddr(Name.Device1, DEVICE1_MAC);
	getDevMACaddr(Name.Device2, DEVICE2_MAC);

	// 指定したNICに「[L2で動作]し[プロトコルヘッダーを含む全てのデータが操作可能]で[全プロトコルを受信する(プロミスキャス)]」Rawソケットをバインドする
	if ((Device[0].soc = InitRawSocket(Name.Device1, 1, 0)) == -1) {
		printf("InitRawSocket:error :%s\n", Name.Device1);
		return (-1);
	}
	printf("%s.socket is OK\n", Name.Device1);
	
	//　Device1と同様↑
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
