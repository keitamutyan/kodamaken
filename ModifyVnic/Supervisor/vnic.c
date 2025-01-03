#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/in.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/fcntl.h>
#include <linux/poll.h>

#define	PRINT(fmt, args...)	printk("Supervisor:" fmt, ## args)
#define	ENABLE	1
#define	POOL_SIZE	8
#define	BUFF_SIZE	16
#define	PACKET_SIZE	4096	
#define	MODULE_NAME	"Supervisor"
#define	DEV_NAME	"Supervisor"

static int pool_size=POOL_SIZE;
module_param(pool_size, int, 0);


typedef struct vn_packet {
  int		len;
  unsigned char data[PACKET_SIZE];//1500 octets ethernet frame
} PACKET;

typedef struct {
  struct net_device_stats stats;
} NET_PRIV;

static struct semaphore sem;
static wait_queue_head_t wait_queue;

static PACKET	packet[BUFF_SIZE];
static int	next_read;
static int	next_write;
static	dev_t	cdev_id;
static	struct cdev	cdev;

static struct net_device	*vn_dev;
static NET_PRIV			*net_priv;
static unsigned char mac_address[6]={0x00,0x00,0xc0,0xa8,0x14,0x51};
//MODULE_LICENSE("GPL");
//MODULE_AUTHOR("yg");

/*********CHARACTOR DEVICE  CALL BACKS ****************/
static int ap_open(struct inode *inode, struct file *file)
{
  return 0;
}

static int ap_release(struct inode *indeo, struct file *file)
{
  return 0;
}

static unsigned int ap_poll(struct file *file, poll_table *poll_table)
{          printk("poll\n");
  unsigned int mask=0;
  down(&sem);
  poll_wait(file, &wait_queue, poll_table);
  //読み込めるものがあるか?
  if(next_write!=next_read){
    mask |= (POLLIN | POLLRDNORM);
  }
  up(&sem);
  return mask;
}


static ssize_t ap_read( struct file *file, char __user *buff, size_t count, loff_t	*offp)
{
  printk("ap_read");
 
}

static ssize_t ap_write(struct file *file, const char __user *ubuff, size_t count ,loff_t *offp)
{
  printk("ap_write\n");

  struct sk_buff *skb;
  struct ethhdr *eth;

  //パラメータチェック
  if(count > 1600 ) {
    net_priv->stats.rx_dropped++;
    return -EINVAL;
  }

  //	//インタフェース状態を検査
  //	if(!(vn_dev->flags & IFF_UP)){
  //		net_priv->stats.rx_dropped++;
  //		return -EBUSY;
  //	}

  //ソケットバッファを確保する
  skb = dev_alloc_skb(count+2);
  if(skb==NULL){
    net_priv->stats.rx_dropped++;
    return -ENOMEM;
  }

  //ヘッダ領域を確保する
  //MACヘッダは14バイトなので、IPヘッダ開始位置を4バイトアライン
  //するために、2バイトを確保しておく
  skb_reserve(skb, 2);

  //データを書き込む
  if(copy_from_user( skb_put(skb, count), ubuff, count)){
    net_priv->stats.rx_errors++;
    return count;
  }
  //MACアドレスを書き込む
  eth=(struct ethhdr *)(skb->data);

  //	eth->h_proto=htons(ETH_P_ARP);
  //	memcpy(eth->h_source,mac_address,ETH_ALEN);
  memcpy(eth->h_dest  ,mac_address,ETH_ALEN);
  //skb設定
  skb->dev = vn_dev;
  skb->protocol = eth_type_trans(skb, vn_dev);
  //skb->ip_summed = CHECKSUM_UNNECESSARY;
  net_priv->stats.rx_packets++;
  net_priv->stats.rx_bytes += count;
  netif_rx(skb);
  return count;

}

/*********NETWROK INTERFACE CALL BACKS ****************/
//--------------------------------------------------------IOCTL
static int vn_ioctl(struct net_device *net,struct ifreq *req, int cmd)
{
  //NOP 
  printk("VN_ioctl\n");
  return 0;
}
//--------------------------------------------------------OPEN 
static int vn_open(struct net_device *net)
{
  printk("VN_open\n");
  netif_start_queue(net);
  return 0;
}
//--------------------------------------------------------CLOSE
static int vn_stop(struct net_device *net)
{
  printk("stop\n");
  //受信キューの停止
  netif_stop_queue(net);
  return 0;
}

static int vn_config(struct net_device *net,struct ifmap *map)
{
  printk("config\n");
  return 0;
}

static struct net_device_stats *vn_stats(struct net_device *net)
{
  return &net_priv->stats;
}

static int  vn_tx(struct sk_buff *skb, struct net_device *net)
{
  printk("tx\n");
 
  dev_kfree_skb_any(skb);
  //	dev_kfree_skb_any(skb1);

  return 0;
}


/***********************************/
static struct net_device_ops interceptor_netdev_ops
={
  .ndo_open=vn_open,
  .ndo_stop=vn_stop,
  .ndo_set_config=vn_config,
  .ndo_start_xmit=vn_tx,
  .ndo_do_ioctl=vn_ioctl,
  .ndo_get_stats=vn_stats,
};


static void vn_init(struct net_device *dev)
{
  ether_setup(dev);
  //MAC アドレスの設定
  memcpy(dev->dev_addr,mac_address,ETH_ALEN);

  dev->netdev_ops =&interceptor_netdev_ops;

  //	dev->open=vn_open;
  //	dev->stop=vn_stop;
  //	dev->set_config=vn_config;
  //	dev->hard_start_xmit=vn_tx;
  //	dev->do_ioctl=vn_ioctl;
  //	dev->get_stats=vn_stats;
  //	dev->flags |= IFF_NOARP;
  net_priv=netdev_priv(dev);
  memset(net_priv,0,sizeof(NET_PRIV));
  PRINT("driver initialized\n");
}

static struct file_operations fops={
  .owner=THIS_MODULE,
  //.open=ap_open,
  .release=ap_release,
  .read=ap_read,
  .write=ap_write,
  //	.poll=ap_poll
};


static void __exit ext_vn(void)
{
  if(vn_dev!=NULL){
    unregister_netdev(vn_dev);
    free_netdev(vn_dev);
    vn_dev=NULL;
  }
  cdev_del(&cdev);
  unregister_chrdev_region(cdev_id,1);
}

static int __init init_vn(void)
{
  int ret=-ENOMEM;
  int	result;
	
  init_waitqueue_head(&wait_queue);
  //init_MUTEX(&sem);
  sema_init(&sem,1);
  //vn_dev=alloc_netdev(sizeof(NET_PRIV), DEV_NAME, vn_init);
  vn_dev=alloc_netdev(sizeof(NET_PRIV), DEV_NAME, NET_NAME_UNKNOWN, vn_init);
  if(vn_dev==NULL){
    goto out;
  }
  ret=-ENODEV;
  result=register_netdev(vn_dev);
  if(result!=0){
    PRINT("error register_netdev=%i\n",result);
    goto err1;
  }else{
    PRINT("driver registered\n");
  }
  ret=alloc_chrdev_region(&cdev_id, 0, 1, MODULE_NAME);
  if(ret<0){
    goto err1;
  }
  cdev_init(&cdev, &fops);
  cdev.owner=THIS_MODULE;
  ret=cdev_add(&cdev, cdev_id, 1);
  if(ret < 0){
    goto err2;
  }
  next_write=0;
  next_read=0;
  //正常終了
  return 0;
  //エラー後処理
 err2:
  cdev_del(&cdev);
  unregister_chrdev_region(cdev_id, 1);
 err1:
  unregister_netdev(vn_dev);
  free_netdev(vn_dev);
 out:
  return -1;
}

module_init(init_vn);
module_exit(ext_vn);
