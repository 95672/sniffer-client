#include "def_cap.h"
#include "cap_my.h"
#include "main_var.h"

pcap_t * init_dev_comm()
{
pcap_if_t *alldevs;//�豸ָ��1
pcap_if_t *d;//�豸ָ��2
int inum;
int i=0;
pcap_t *adhandle;//�豸ָ��3
char errbuf[PCAP_ERRBUF_SIZE];
    
    /* ��ȡ�����豸�б� 
	pcap_if_t *alldevs; �����豸�б�  errbuf �Ǵ�����Ϣ��
	*/
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
       printf("pcap_find ����");
	

    
    /* ��ӡ�б�
	pcap_if_t *d;  �м�ָ��
	*/
    for(d=alldevs; d; d=d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" �豸��ȡʧ�ܣ���\n");
    }
    
    if(i==0)
    {
        printf("\nδ���ֿ��õ��豸�ӿڣ������豸��.\n");
    }
    
    printf("��������Ҫ�������豸���룺 (1-%d):",i);
    scanf("%d", &inum);
    
    if(inum < 1 || inum > i)
    {
        printf("\n�����ӿڷ�Χ��.\n");
        /* �ͷ��豸�б� */
        pcap_freealldevs(alldevs);
    }
    
    /* ��ת��ѡ�е������� */
    for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
	dev_add =d;
    

    /* ���豸 */
	if ( (adhandle= pcap_open_live(d->name/*�豸��*/,65536/*��С*/,1/*ģʽ*/,1000/*��ʱʱ��*/,errbuf)) == NULL)
    {
        fprintf(stderr,"\n�޷���������. %s ��һ�����ܱ�winpcap֧�ֵ��豸\n", d->name);
        pcap_freealldevs(alldevs);
    }

	 if(d->addresses != NULL)
	 {
	
        netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	 }
    else
	{
	 printf("û�м�⵽�������룬Ĭ��ʧ�ܣ�\n");
	 }

	 printf("\n�����豸��,��ѡ�е��豸: %s...\n", d->description);
    /* �ͷ��豸�б� */
    pcap_freealldevs(alldevs);
	
	return adhandle;
}

pcap_t * init_dev_comm_name( pcap_if_t *dev_add)
{
	pcap_t *adhandle;
	char errbuf[120];
	if ( (adhandle= pcap_open_live(dev_add->name/*�豸��*/,65536/*��С*/,1/*ģʽ*/,1000/*��ʱʱ��*/,errbuf)) == NULL)
    {
        fprintf(stderr,"\n�޷���������. %s ��һ�����ܱ�winpcap֧�ֵ��豸\n", dev_add->name);
      
    }


	return adhandle;






}
