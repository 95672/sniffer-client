//#include "def_cap.h"
//
//
extern pcap_t *dev_comm_forall;
extern char filepath[];
extern int ip_save_num;
extern ip_address ip_save[50];
extern pthread_t thread[50];//这里是线程程数量
extern pthread_mutex_t mut;//互斥锁
extern int threadnum;//线程数量
extern  u_int netmask;//局域网子网掩码
extern  pcap_if_t *dev_add;
extern int allliuliang;//总流量
extern thread_fen thread_f[2000];//缓冲区  专门用于线程数据包获取   取过了的就为1 初始化为0
extern  thread_in  thread_ins;
extern  int datanum_pack;
extern  ipcomst ipfile[50];
 //===========网络线程控制变量，发送变量
extern   bool threadconnum;
extern   conlists *conlistview;