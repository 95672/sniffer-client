#include "def_cap.h"

int cap_send(pcap_t *dev,u_char *packetdata,int len)
{

	pcap_t *fps;
	printf("%d\n",*packetdata);
	printf("���ݰ���СΪ��%d\n",len);
	if(pcap_sendpacket(dev,packetdata,len)!=0)
	{
	printf("���ݰ�����ʧ��!\n");
	return 0;
	}
	printf("sdf");
	getchar();

	return 0;

}