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

#define XOR_KEY 0xAA
#define BROADCAST_IP "255.255.255.255"
#define BUFFER_SIZE 2048

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

    sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("ソケット作成エラー");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, device, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("デバイスインデックス取得エラー");
        close(sock);
        return -1;
    }

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

// パケット処理
void process_packet(int recv_sock, int send_sock) {
    unsigned char buffer[BUFFER_SIZE];
    ssize_t len = recv(recv_sock, buffer, BUFFER_SIZE, 0);
    if (len < 0) {
        perror("受信エラー");
        return;
    }

    struct ether_header *eth = (struct ether_header *)buffer;
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ether_header));

    // デバッグ出力
    printf("Received packet:\n");
    printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
           eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
           eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

    if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
        printf("Processing IP packet...\n");

        // 宛先IPアドレスを暗号化してオプション領域に格納
        unsigned char encrypted_ip[4];
        memcpy(encrypted_ip, &iph->daddr, 4);
        xor_encrypt(encrypted_ip, 4);
        memcpy((unsigned char *)(iph + 1), encrypted_ip, 4);
        iph->daddr = inet_addr(BROADCAST_IP);
    }

    // パケット送信
    if (send(send_sock, buffer, len, 0) < 0) {
        perror("送信エラー");
    } else {
        printf("Packet forwarded successfully.\n");
    }
}

int main() {
    const char *vNIC = "Supervisor";
    const char *NIC = "enp1s0";
    int vNIC_sock, NIC_sock;

    vNIC_sock = init_raw_socket(vNIC);
    NIC_sock = init_raw_socket(NIC);
    if (vNIC_sock < 0 || NIC_sock < 0) {
        fprintf(stderr, "ソケットの初期化に失敗しました。\n");
        return 1;
    }

    printf("クライアントブリッジプログラムを開始します。\n");

    while (1) {
        process_packet(vNIC_sock, NIC_sock); // vNIC -> NIC
        process_packet(NIC_sock, vNIC_sock); // NIC -> vNIC
    }

    close(vNIC_sock);
    close(NIC_sock);
    return 0;
}

