#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#define XOR_KEY 0xAA  // XOR暗号化キー
#define BROADCAST_IP "255.255.255.255"  // ブロードキャストアドレス
#define BUFFER_SIZE 2048  // パケットバッファサイズ

// XOR暗号化関数
void xor_encrypt(unsigned char *data, int len) {
    for (int i = 0; i < len; i++) {
        data[i] ^= XOR_KEY;
    }
}

// RAWソケット初期化
int init_raw_socket(const char *device) {
    int sock;
    struct sockaddr_ll sll;
    struct ifreq ifr;

    // RAWソケット作成
    sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("ソケット作成エラー");
        return -1;
    }

    // デバイス名を設定
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, device, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("デバイスインデックス取得エラー");
        close(sock);
        return -1;
    }

    // ソケットをデバイスにバインド
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = PF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("ソケットバインドエラー");
        close(sock);
        return -1;
    }

    return sock;
}

int main() {
    const char *vNIC = "Supervisor";  // 仮想NIC名
    const char *NIC = "enp1s0";       // 実NIC名
    int vNIC_sock, NIC_sock;
    unsigned char buffer[BUFFER_SIZE];
    ssize_t len;

    // ソケット初期化
    vNIC_sock = init_raw_socket(vNIC);
    NIC_sock = init_raw_socket(NIC);
    if (vNIC_sock < 0 || NIC_sock < 0) {
        fprintf(stderr, "ソケットの初期化に失敗しました。\n");
        return 1;
    }

    printf("クライアントPCのブリッジプログラムを開始します。\n");

    while (1) {
        // vNICからパケットを受信
        len = recv(vNIC_sock, buffer, BUFFER_SIZE, 0);
        if (len < 0) {
            perror("受信エラー");
            continue;
        }

        // IPヘッダーにアクセス
        struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ether_header));

        // 宛先IPアドレスを取得して表示
        struct in_addr dest_ip;
        dest_ip.s_addr = iph->daddr;
        printf("受信パケットの宛先IPアドレス: %s\n", inet_ntoa(dest_ip));

        // 宛先IPを暗号化してオプション領域に保存
        unsigned char encrypted_ip[4];
        memcpy(encrypted_ip, &iph->daddr, 4);
        xor_encrypt(encrypted_ip, 4);
        memcpy((unsigned char *)(iph + 1), encrypted_ip, 4);

        // 宛先IPをブロードキャストアドレスに変更
        iph->daddr = inet_addr(BROADCAST_IP);

        // NICにパケットを転送
        if (send(NIC_sock, buffer, len, 0) < 0) {
            perror("送信エラー");
        } else {
            printf("パケットを送信しました（サイズ: %zd バイト）。\n", len);
        }
    }

    close(vNIC_sock);
    close(NIC_sock);
    return 0;
}
