//#include "def_cap.h"
//
//
extern pcap_t *dev_comm_forall;
extern char filepath[];
extern int ip_save_num;
extern ip_address ip_save[50];
extern pthread_t thread[50];//�������̳߳�����
extern pthread_mutex_t mut;//������
extern int threadnum;//�߳�����
extern  u_int netmask;//��������������
extern  pcap_if_t *dev_add;
extern int allliuliang;//������
extern thread_fen thread_f[2000];//������  ר�������߳����ݰ���ȡ   ȡ���˵ľ�Ϊ1 ��ʼ��Ϊ0
extern  thread_in  thread_ins;
extern  int datanum_pack;
extern  ipcomst ipfile[50];
 //===========�����߳̿��Ʊ��������ͱ���
extern   bool threadconnum;
extern   conlists *conlistview;