//#include "def_cap.h"
//#include "cap_my.h"
//void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
//int base_cap()
//{
//pcap_if_t *alldevs;
//pcap_if_t *d;
//int inum;
//int i=0;
//pcap_t *adhandle;
//char errbuf[PCAP_ERRBUF_SIZE];
//    
//    /* 获取本机设备列表 
//	pcap_if_t *alldevs; 这是设备列表  errbuf 是错误信息；
//	*/
//	if(pcap_findalldevs(&alldevs, errbuf) == -1)
//		return 1;
//	
//
//    
//    /* 打印列表
//	pcap_if_t *d;  中间指针
//	*/
//    for(d=alldevs; d; d=d->next)
//    {
//        printf("%d. %s", ++i, d->name);
//        if (d->description)
//            printf(" (%s)\n", d->description);
//        else
//            printf(" (No description available)\n");
//    }
//    
//    if(i==0)
//    {
//        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
//        return -1;
//    }
//    
//    printf("Enter the interface number (1-%d):",i);
//    scanf("%d", &inum);
//    
//    if(inum < 1 || inum > i)
//    {
//        printf("\nInterface number out of range.\n");
//        /* 释放设备列表 */
//        pcap_freealldevs(alldevs);
//        return -1;
//    }
//    
//    /* 跳转到选中的适配器 */
//    for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
//    
//    /* 打开设备 */
//	if ( (adhandle= pcap_open_live(d->name/*设备名*/,65536/*大小*/,1/*模式*/,1000/*超时时间*/,errbuf)) == NULL)
//    {
//        fprintf(stderr,"\n无法打开配置器. %s is not supported by WinPcap\n", d->name);
//        pcap_freealldevs(alldevs);
//        return -1;
//    }
//
//    printf("\nlistening on %s...\n", d->description);
//    
//    /* 释放设备列表 */
//    pcap_freealldevs(alldevs);
//    
//    /* 开始捕获 */
//    pcap_loop(adhandle, 0, packet_handler, NULL);
//    
//    return 0;
//}
//
//void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
//{
//    struct tm *ltime;
//    char timestr[16];
//    time_t local_tv_sec;
//    
//    /* 将时间戳转换成可识别的格式 */
//    local_tv_sec = header->ts.tv_sec;
//    ltime=localtime(&local_tv_sec);
//    strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
//    
//    printf("%s,%.6d len:%d,leng_data:%d\n", timestr, header->ts.tv_usec, header->len,sizeof(pkt_data));
//    
//}