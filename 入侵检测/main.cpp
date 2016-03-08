#include "def_cap.h"
#include "cap_my.h"
extern void send_packet_test();
 char filepath[]="C:\\winpcap_dump\\";
 //===========================================
 pcap_t *dev_comm_forall;//选择的公共设备——接受设备或者发射设备
 pthread_t thread[50];//这里是线程程数量
 pthread_t netserver;
 pthread_mutex_t mut;//互斥锁
 int threadnum;//线程数量
 pcap_if_t *dev_add;//公用设备名称变量
 //\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
 
/*这两个是配套的*/
 //ip_address ip_save[50];
 int ip_save_num;
//==================
 u_int netmask;//子网掩码
 int allliuliang;
 //线程缓冲区
 thread_fen thread_f[2000]; 
 thread_in  thread_ins;
 //----------------------------
 int datanum_pack;//循环缓冲的时候准备的序号
 ipcomst ipfile[50];//ipfile 文件中储存的50个IP连接。
 //===========网络线程控制变量，发送变量
  bool threadconnum;
  conlists *conlistview;
 //===========



void* thread_1(void *)  
{  
		  SOCKET sockServer;     // 服务端 Socket
          SOCKADDR_IN addrServer;// 服务端地址
          SOCKET sockClient;     // 客户端 Scoket
          SOCKADDR_IN addrClient;// 客户端地址
          WSADATA wsaData;       // winsock 结构体
          WORD wVersionRequested;// winsock 的版本
		  wVersionRequested = MAKEWORD( 2, 2 );
		  int len;
    sockServer = socket(AF_INET, SOCK_STREAM, 0);
    addrServer.sin_addr.S_un.S_addr = htonl(INADDR_ANY); 
    addrServer.sin_family = AF_INET;                  
    addrServer.sin_port = htons(9999);                 
    bind(sockServer, (SOCKADDR *)&addrServer, sizeof(SOCKADDR));
    listen(sockServer, 5); 
    printf("本地监听端口:9999\n请使用审计端建立连接.....\n");
    len = sizeof(SOCKADDR);
		sockClient = accept(sockServer, (SOCKADDR *)&addrClient, &len);
		char *sendBuf = (char *)malloc(sizeof(struct conlist));
		setsockopt(sockClient, SOL_SOCKET, SO_KEEPALIVE, sendBuf, sizeof(struct conlist));//使用KEEPALIVE
         setsockopt(sockClient, IPPROTO_TCP, TCP_NODELAY, sendBuf, sizeof(struct conlist));//禁用NAGLE算法
		printf("连接已建立，正在传输数据.......\n");
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



	









	printf("本机活跃的网卡列表如下：\n");




	//==============================================================原始数据
	//=================
	threadnum =0;
	allliuliang=0;
	datanum_pack =0;
	////=================
	////-------------------------初始化缓冲区域
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
        printf("\n这个设备不在局域网内.\n");
        return -1;
    }
		 pthread_create(&netserver, NULL,thread_1, &thread_ins);
		  pcap_loop(dev_comm_forall, 0, listen_base, NULL);



	return 0;
}

