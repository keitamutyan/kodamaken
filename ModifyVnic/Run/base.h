#define FLAG_FREE 0
#define FLAG_OK 1
#define FLAG_NG -1

typedef struct {
  int soc;
  u_char hwaddr[6];
  struct in_addr addr,subnet,netmask;
} DEVICE;

typedef struct _data_buf_{
  struct _data_buf_ *next;
  struct _data_buf_ *before;
  time_t t;
  int size;
  unsigned char *data;
}DATA_BUF;

typedef struct {
  DATA_BUF *top;
  DATA_BUF *bottom;
  unsigned long dno;
  unsigned long inBucketSize;
  pthread_mutex_t mutex;
}SEND_DATA;

typedef struct {
  int flag;
  int deviceNo;
  in_addr_t addr;
  unsigned char hwaddr[6];
  time_t LastTime;
  SEND_DATA sd;
}IP2MAC;

typedef struct {
  unsigned char original[7];
  unsigned char current[7];
} HARDWARE;

typedef struct {
	char *Device1;
	char *Device2;
} DEVICE_NAME;

unsigned char address[4];
char hwaddr[18];
unsigned char u_hwaddr[6];

