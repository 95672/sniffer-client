#include "def_cap.h"

int cap_send(pcap_t *dev,u_char *packetdata,int len)
{

	pcap_t *fps;
	printf("%d\n",*packetdata);
	printf("数据包大小为：%d\n",len);
	if(pcap_sendpacket(dev,packetdata,len)!=0)
	{
	printf("数据包发送失败!\n");
	return 0;
	}
	printf("sdf");
	getchar();

	return 0;

}