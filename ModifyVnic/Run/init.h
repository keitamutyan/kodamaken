void getDevMACaddr(char *DevName, u_char *MACaddr);
int InitRawSocket(char *device ,int promiscFlag ,int ipOnly );
char *MACaddr_ntoa(u_char *hwaddr ,char *buf ,socklen_t size );
unsigned char *getSerialNum(char* source,unsigned char *serial);
int get_ifhw(char *devname,char *buf,socklen_t size,unsigned char *u_buf);
int get_ifip(char *devname,unsigned char *address );
int DisableIpForward();
