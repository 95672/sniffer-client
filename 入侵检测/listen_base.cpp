#include "def_cap.h"
#include "main_var.h"


ip_address ip_thislisten_noew;

extern int com_file_ipsa(struct ip_address *ip,struct ip_address *ips);
extern pcap_t * init_dev_comm_name( pcap_if_t *dev_add);
void dispatcher_handler(u_char *state, const struct pcap_pkthdr *header, const u_char *pkt_data);
int num_verandpacket;//最后监听线程用来标记的


void listen_base(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{

//struct tm *ltime;
//char timestr[16];
//struct timeval st_ts;
//time_t local_tv_sec;
ip_header *ih;
//local_tv_sec = header->ts.tv_sec;
//ltime=localtime(&local_tv_sec);
    //strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
	//char path[]="C:\\winpcap_dump\\localhost.txt";
	//FILE *thisfile;
 //   thisfile = fopen(path,"a+");
	//if(thisfile==NULL)
	//	printf("this is why error\n");
	//printf("%d        %d\n",allliuliang,header->len);
	//allliuliang = allliuliang + header->len;
	conlistview = (struct conlist *)malloc(sizeof(struct conlist));




	ih = (ip_header *)(pkt_data +14);//IP头部
	tcp_header *tcp_h;//tcp头部
	udp_header *udp_h;//udp头部
	unsigned int sport;
	unsigned int dport;
	char *proto;
	/*以下为向缓冲区内加入数据包的代码*/
		if(datanum_pack ==2000)
		        datanum_pack=0;
		
			    //pthread_mutex_lock(&thread_f[datanum_pack].lock);
				thread_f[datanum_pack].packet_data=(u_char *)pkt_data;
	            datanum_pack++;
				for(int nu =0;nu<50;nu++)
				thread_f[datanum_pack].th[nu]=0;
				//pthread_mutex_unlock(&thread_f[datanum_pack].lock);
				conlistview->zero =0;
			    conlistview->zero1=0;
		//----------------------------------------------
				/*总体分析模块*/
				conlistview->tlen = ih->tlen;
					if(ih->proto==6)
						{
							proto ="TCP";
							tcp_h =(tcp_header *)((u_char *)ih + (u_int)(ih->ver_len&0x0000000f)*4); 
							dport = ntohs(tcp_h->dst_port);
							sport = ntohs(tcp_h->src_port);
					      //================================准备发送变量
							conlistview->zero =0;
							conlistview->zero1=0;
							conlistview->dst_port = dport;
							conlistview->src_port  = sport;
							conlistview->ipdec=ih->daddr;
							conlistview->ipsrc=ih->saddr;
							conlistview->ip_pro=6;
							conlistview->fin = tcp_h->fin;
							conlistview->ack =tcp_h->ack;
							conlistview->rst =tcp_h->rst;
							conlistview->syn=tcp_h->syn;
							conlistview->ackseq=tcp_h->ack_seq;
							conlistview->seq = tcp_h->seq;
							
							threadconnum =true;
							//================================IP层准备完成
							//if(dport==20||sport==21)
							//	proto ="FTP";
							//else if(dport ==22||sport ==22)
							//proto ="SSH";
							//else if(dport==23||sport==23)
							//	proto = "TELNET";
							//else if(dport==24||sport==24)
							//	proto = "private mail";
							//else if (dport==25||sport==25)
							//	proto = "SMTP";
							//else if(dport==27||sport==27)
							//	proto = "NSF-FE";
							//else if(dport==80||dport==8080||sport==80)
							//{	proto ="HTTP";
						
							//conlistview->dst_port = ntohs(tcp_h->dst_port);;
							//conlistview->src_port  = ntohs(tcp_h->src_port);
							//conlistview->ipdec=ih->daddr;
							//conlistview->ipsrc=ih->saddr;
							//threadconnum =true;
							//}
							//else if(dport==443||sport==443)
							//	{
							//		proto = "HTTPS";
							//		/*HTTP文件还原子序列*/


							//   }
							

						}
						else if(ih->proto==1)
						{
							proto="ICMP";
						/*	fprintf(thisfile,"%d.%d.%d.%d -> %d.%d.%d.%d %s\n",ih->saddr.byte1,ih->saddr.byte2,ih->saddr.byte3,ih->saddr.byte4,
							ih->daddr.byte1,ih->daddr.byte2,ih->daddr.byte3,ih->daddr.byte4,proto);
													fflush(thisfile);*/

					    }
						else if (ih->proto==2)
							proto="IGMP";
						else if(ih->proto==4)
							proto ="IP";
						else if(ih->proto==17)
						{
							proto ="UDP";
							udp_h = (udp_header *) ((u_char *)ih +(u_int)(ih->ver_len&0x0000000f)*4); 

                          	
							conlistview->dst_port = ntohs(udp_h->dport);;
							conlistview->src_port  = ntohs(udp_h->sport);
							conlistview->ipdec=ih->daddr;
							conlistview->ipsrc=ih->saddr;
							conlistview->ip_pro=17;
							conlistview->syn=0;
							conlistview->ack=0;
							conlistview->fin=0;
							conlistview->seq=0;
							conlistview->ackseq=0;
							threadconnum =true;
						}
						else 
							proto ="UNKONW";

				/*总体分析模块结束*/




}



