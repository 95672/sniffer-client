#include "def_cap.h"
#include "cap_my.h"
extern void send_packet_test();
 char filepath[]="C:\\winpcap_dump\\";
 //===========================================
 pcap_t *dev_comm_forall;//ѡ��Ĺ����豸���������豸���߷����豸
 pthread_t thread[50];//�������̳߳�����
 pthread_t netserver;
 pthread_mutex_t mut;//������
 int threadnum;//�߳�����
 pcap_if_t *dev_add;//�����豸���Ʊ���
 //\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
 
/*�����������׵�*/
 //ip_address ip_save[50];
 int ip_save_num;
//==================
 u_int netmask;//��������
 int allliuliang;
 //�̻߳�����
 thread_fen thread_f[2000]; 
 thread_in  thread_ins;
 //----------------------------
 int datanum_pack;//ѭ�������ʱ��׼�������
 ipcomst ipfile[50];//ipfile �ļ��д����50��IP���ӡ�
 //===========�����߳̿��Ʊ��������ͱ���
  bool threadconnum;
  conlists *conlistview;
 //===========



void* thread_1(void *)  
{  
		  SOCKET sockServer;     // ����� Socket
          SOCKADDR_IN addrServer;// ����˵�ַ
          SOCKET sockClient;     // �ͻ��� Scoket
          SOCKADDR_IN addrClient;// �ͻ��˵�ַ
          WSADATA wsaData;       // winsock �ṹ��
          WORD wVersionRequested;// winsock �İ汾
		  wVersionRequested = MAKEWORD( 2, 2 );
		  int len;
    sockServer = socket(AF_INET, SOCK_STREAM, 0);
    addrServer.sin_addr.S_un.S_addr = htonl(INADDR_ANY); 
    addrServer.sin_family = AF_INET;                  
    addrServer.sin_port = htons(9999);                 
    bind(sockServer, (SOCKADDR *)&addrServer, sizeof(SOCKADDR));
    listen(sockServer, 5); 
    printf("���ؼ����˿�:9999\n��ʹ����ƶ˽�������.....\n");
    len = sizeof(SOCKADDR);
		sockClient = accept(sockServer, (SOCKADDR *)&addrClient, &len);
		char *sendBuf = (char *)malloc(sizeof(struct conlist));
		setsockopt(sockClient, SOL_SOCKET, SO_KEEPALIVE, sendBuf, sizeof(struct conlist));//ʹ��KEEPALIVE
         setsockopt(sockClient, IPPROTO_TCP, TCP_NODELAY, sendBuf, sizeof(struct conlist));//����NAGLE�㷨
		printf("�����ѽ��������ڴ�������.......\n");
		while (1)
    {
		
     
		if(threadconnum)
		{
			if(conlistview->dst_port>65535||conlistview->dst_port<0)
				continue;
			if(conlistview->src_port>65535||conlistview->src_port<0)
				continue;
			if(conlistview->ip_pro>20||conlistview->ip_pro<0)
				continue;

			
			memcpy(sendBuf,conlistview,sizeof(struct conlist));
         int ss= send(sockClient, sendBuf, sizeof(struct conlist), 0);
		// printf("%d.%d.%d.%d  %d.%d.%d.%d  p:%d  p2:%d pro:%d\n ",conlistview->ipdec.byte1,conlistview->ipdec.byte2,conlistview->ipdec.byte3,conlistview->ipdec.byte4,conlistview->ipsrc.byte1,conlistview->ipsrc.byte2,conlistview->ipsrc.byte3,conlistview->ipsrc.byte4,conlistview->dst_port,conlistview->src_port,conlistview->ip_pro);
		threadconnum=false;
		//getchar();
		}
		else
			continue;
		
    }

	return NULL;
}

int main(void* arg)
{

	//send_packet_test();



	









	printf("������Ծ�������б����£�\n");




	//==============================================================ԭʼ����
	//=================
	threadnum =0;
	allliuliang=0;
	datanum_pack =0;
	////=================
	////-------------------------��ʼ����������
	for(int ls =0;ls<50;ls++)
		for(int ll=0;ll<200;ll++)
			thread_f[ls].th[ll]=1;
	//-------------------------
	    //init_file_ipt();
		//printf("------------------------------%d\n",sizeof( struct conlist));
		//getchar();
		dev_comm_forall = init_dev_comm();
		 if(pcap_datalink(dev_comm_forall) != DLT_EN10MB)
    {
        printf("\n����豸���ھ�������.\n");
        return -1;
    }
		 pthread_create(&netserver, NULL,thread_1, &thread_ins);
		  pcap_loop(dev_comm_forall, 0, listen_base, NULL);



	return 0;
}

