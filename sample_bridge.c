#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <poll.h>
#include <fcntl.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>

// 環境に合うようにインターフェース名を変更
#define INTERFACE1 "enp1s0"  // 実際のNIC
#define INTERFACE2 "Supervisor" // 実際のvNIC

int soc1, soc2;
int EndFlag = 0;

// 生ソケットの初期化
int InitRawSocket(const char *device) {
    int sock;
    struct sockaddr_ll sll;
    struct ifreq ifr;

    // ソケット作成
    sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    // デバイス名設定
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name) - 1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl");
        close(sock);
        return -1;
    }

    // ソケットのバインド
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

// ブリッジの動作
int Bridge() {
    struct pollfd fds[2];
    unsigned char buf[2048];
    int nready, size;

    fds[0].fd = soc1;
    fds[0].events = POLLIN | POLLERR;
    fds[1].fd = soc2;
    fds[1].events = POLLIN | POLLERR;

    while (!EndFlag) {
        // 2つのインターフェースのポーリング
        nready = poll(fds, 2, 100);
        if (nready == -1) {
            if (errno != EINTR) {
                perror("poll");
            }
            continue;
        }

        for (int i = 0; i < 2; i++) {
            if (fds[i].revents & POLLIN) {
                size = read(fds[i].fd, buf, sizeof(buf));
                if (size <= 0) {
                    perror("read");
                } else {
                    printf("Packet received on %s, size: %d bytes\n", (i == 0) ? INTERFACE1 : INTERFACE2, size);

                    // 反対側のインターフェースに送信
                    if (write(fds[1 - i].fd, buf, size) <= 0) {
                        perror("write");
                    } else {
                        printf("Packet forwarded to %s\n", (i == 0) ? INTERFACE2 : INTERFACE1);
                    }
                }
            }
        }
    }
    return 0;
}

// 終了シグナル処理
void EndSignal(int sig) {
    EndFlag = 1;
}

int main() {
    // ソケットの初期化
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

    // シグナルハンドラの設定
    signal(SIGINT, EndSignal);
    signal(SIGTERM, EndSignal);

    printf("Bridge start\n");
    Bridge();
    printf("Bridge end\n");

    close(soc1);
    close(soc2);

    return 0;
}

