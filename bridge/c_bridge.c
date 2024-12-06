#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <fcntl.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>

// デバイス名を設定
#define INTERFACE1 "Supervisor"  // vNIC
#define INTERFACE2 "enp1s0"      // NIC
#define XOR_KEY 0xAA             // XOR暗号化キー

int soc1, soc2;
int EndFlag = 0;

// 暗号化関数（XOR方式）
void xor_encrypt(unsigned char *data, int len) {
    for (int i = 0; i < len; i++) {
        data[i] ^= XOR_KEY;
    }
}

// ソケットの初期化
int InitRawSocket(const char *device) {
    int sock;
    struct sockaddr_ll sll;
    struct ifreq ifr;

    sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name) - 1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl");
        close(sock);
        return -1;
    }

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = PF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind");
        close(sock);
        return -1;
    }

    return sock;
}

// ブリッジ動作
int Bridge() {
    unsigned char buf[2048];
    struct ether_header *eth;
    struct iphdr *iph;
    ssize_t size;

    while (!EndFlag) {
        size = read(soc1, buf, sizeof(buf));
        if (size <= 0) {
            perror("read");
            continue;
        }

        eth = (struct ether_header *)buf;
        iph = (struct iphdr *)(buf + sizeof(struct ether_header));

        if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
            // 宛先IPアドレスを暗号化してオプション領域に格納
            unsigned char encrypted_ip[4];
            memcpy(encrypted_ip, &iph->daddr, 4);
            xor_encrypt(encrypted_ip, 4);
            memcpy((unsigned char *)(iph + 1), encrypted_ip, 4);

            // 宛先IPをブロードキャストアドレスに変更
            iph->daddr = htonl(0xFFFFFFFF);

            // 再計算されたIPチェックサム
            iph->check = 0;
            iph->check = checksum((unsigned char *)iph, iph->ihl * 4);
        }

        // NICに送信
        if (write(soc2, buf, size) <= 0) {
            perror("write");
        }
    }

    return 0;
}

// シグナル処理
void EndSignal(int sig) {
    EndFlag = 1;
}

int main() {
    soc1 = InitRawSocket(INTERFACE1);
    if (soc1 == -1) {
        fprintf(stderr, "Error initializing %s\n", INTERFACE1);
        return -1;
    }

    soc2 = InitRawSocket(INTERFACE2);
    if (soc2 == -1) {
        fprintf(stderr, "Error initializing %s\n", INTERFACE2);
        close(soc1);
        return -1;
    }

    signal(SIGINT, EndSignal);

    printf("Client Bridge start\n");
    Bridge();
    printf("Client Bridge end\n");

    close(soc1);
    close(soc2);

    return 0;
}
