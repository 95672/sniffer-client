#include "def_cap.h"
#include "cap_my.h"
#include "main_var.h"

pcap_t * init_dev_comm()
{
pcap_if_t *alldevs;//设备指针1
pcap_if_t *d;//设备指针2
int inum;
int i=0;
pcap_t *adhandle;//设备指针3
char errbuf[PCAP_ERRBUF_SIZE];
    
    /* 获取本机设备列表 
	pcap_if_t *alldevs; 这是设备列表  errbuf 是错误信息；
	*/
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
       printf("pcap_find 错误！");
	

    
    /* 打印列表
	pcap_if_t *d;  中间指针
	*/
    for(d=alldevs; d; d=d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" 设备获取失败！！\n");
    }
    
    if(i==0)
    {
        printf("\n未发现可用的设备接口，请检查设备！.\n");
    }
    
    printf("请输入需要监听的设备号码： (1-%d):",i);
    scanf("%d", &inum);
    
    if(inum < 1 || inum > i)
    {
        printf("\n超出接口范围！.\n");
        /* 释放设备列表 */
        pcap_freealldevs(alldevs);
    }
    
    /* 跳转到选中的适配器 */
    for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
	dev_add =d;
    

    /* 打开设备 */
	if ( (adhandle= pcap_open_live(d->name/*设备名*/,65536/*大小*/,1/*模式*/,1000/*超时时间*/,errbuf)) == NULL)
    {
        fprintf(stderr,"\n无法打开配置器. %s 是一个不能被winpcap支持的设备\n", d->name);
        pcap_freealldevs(alldevs);
    }

	 if(d->addresses != NULL)
	 {
	
        netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	 }
    else
	{
	 printf("没有检测到子网掩码，默认失败！\n");
	 }

	 printf("\n监听设备中,被选中的设备: %s...\n", d->description);
    /* 释放设备列表 */
    pcap_freealldevs(alldevs);
	
	return adhandle;
}

pcap_t * init_dev_comm_name( pcap_if_t *dev_add)
{
	pcap_t *adhandle;
	char errbuf[120];
	if ( (adhandle= pcap_open_live(dev_add->name/*设备名*/,65536/*大小*/,1/*模式*/,1000/*超时时间*/,errbuf)) == NULL)
    {
        fprintf(stderr,"\n无法打开配置器. %s 是一个不能被winpcap支持的设备\n", dev_add->name);
      
    }


	return adhandle;






}
