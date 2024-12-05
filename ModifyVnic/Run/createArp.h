void make_ethernet(struct ether_header *eth, unsigned char *ether_dhost,
                   unsigned char *ether_shost, u_int16_t ether_type);
void make_arp(struct ether_arp *arp, int op, unsigned char *arp_sha,
              unsigned char *arp_spa, unsigned char *arp_tha,
              unsigned char *arp_tpa);
void print_ethernet(struct ether_header *eth);
void print_arp(struct ether_arp *arp);
char *mac_ntoa(unsigned char d[]);
void  create_arp(int soc,unsigned char *address,unsigned char *serial);
