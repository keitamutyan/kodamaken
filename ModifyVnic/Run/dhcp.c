/*
 *for analyzing DHCP_header information
 *Thanks to Samuel Jacob
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
//#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ifaddrs.h>

#define __FAVOR_BSD

#define DHCP_CHADDR_LEN 16
#define DHCP_SNAME_LEN 64
#define DHCP_FILE_LEN 128

struct dhcp_static_part
{
  u_int8_t opcode;
  u_int8_t htype;
  u_int8_t hw_addr_len;
  u_int8_t hops;
  u_int32_t xid;
  u_int16_t secs;
  u_int16_t flags;
  u_int32_t client_ip;
  u_int32_t your_ip;
  u_int32_t server_ip;
  u_int32_t gateway_ip;
  u_int8_t client_haddr[DHCP_CHADDR_LEN];
  char bp_sname[DHCP_SNAME_LEN];
  char bp_file[DHCP_FILE_LEN];
  uint32_t magic_cookie;
  /*
  u_int8_t option1_message_type;
  u_int8_t option1_len;
  u_int8_t option1_type;
  */
  //u_int8_t bp_options[0]; 
};

struct dhcp_options_discover{
  u_int8_t dhcp_message_type;
  u_int8_t len_1;
  u_int8_t p_type;
  u_int8_t client_id;
  u_int8_t len_2;
  u_int8_t hw_type;
  u_char client_mac[6];
};

struct dhcp_options_request{
  u_int8_t dhcp_message_type;
  u_int8_t len_1;
  u_int8_t p_type;
  u_int8_t client_id;
  u_int8_t len_2;
  u_int8_t hw_type;
  u_char client_mac[6];
};

#define DHCP_BOOTREQUEST 1
#define DHCP_BOOTREPLY 2

#define DHCP_HARDWARE_TYPE_10_ETHERNET 1

#define MESSAGE_TYPE_PAD 0
#define MESSAGE_TYPE_REQ_SUBNET_MASK 1
#define MESSAGE_TYPE_ROUTER 3
#define MESSAGE_TYPE_DNS 6
#define MESSAGE_TYPE_DOMAIN_NAME 15
#define MESSAGE_TYPE_REQ_IP 50
#define MESSAGE_TYPE_DHCP 53
#define MESSAGE_TYPE_PARAMETER_REQ_LIST 55
#define MESSAGE_TYPE_CLIENT_IDENTIFIER 61
#define MESSAGE_TYPE_END 255

#define DHCP_OPTION_DISCOVER 1
#define DHCP_OPTION_OFFER 2
#define DHCP_OPTION_REQUEST 3
#define DHCP_OPTION_PACK 4

#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68

#define DHCP_MAGIC_COOKIE 0x63825363

unsigned short in_cksum(unsigned short *addr, int len){

  register int sum = 0;
  u_short answer = 0;
  register u_short *w = addr;
  register int nleft = len;
  while(nleft > 1){
    sum += *w++;
    nleft -= 2;
  }
  if(nleft == 1){
    *(u_char *)(&answer) = *(u_char *) w;
    sum += answer;
  }
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  answer = ~sum;
  return(answer);

}
