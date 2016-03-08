#include "def_cap.h"
#include "cap_my.h"
u_int16_t in_cksum (u_int16_t * addr, int len)  
{  
 int     nleft = len;  
 u_int32_t sum = 0;  
 u_int16_t *w = addr;  
 u_int16_t answer = 0;  
  
 /* 
 * Our algorithm is simple, using a 32 bit accumulator (sum), we add 
 * sequential 16 bit words to it, and at the end, fold back all the 
 * carry bits from the top 16 bits into the lower 16 bits. 
 */  
 while (nleft > 1) {  
  sum += *w++;  
  nleft -= 2;  
 }  
 /* mop up an odd byte, if necessary */  
 if (nleft == 1) {  
  * (unsigned char *) (&answer) = * (unsigned char *) w;  
  sum += answer;  
 }  
  
 /* add back carry outs from top 16 bits to low 16 bits */  
 sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */  
 sum += (sum >> 16);     /* add carry */  
 answer = ~sum;     /* truncate to 16 bits */  
 return (answer);  
} 

void send_packet_test()
{


  pcap_t *dev_comm_forall;
		packettest *packettests =(struct packettest *)malloc(sizeof(packettest));
	printf("%d\n",sizeof(unsigned char));
	memset(packettests,0,sizeof(struct packettest));

/*链路层包装*/
	packettests->mac.decmac[0] =0xc0; 
    packettests->mac.decmac[1]  = 0x01; 
    packettests->mac.decmac[2]  = 0x13;     
    packettests->mac.decmac[3]  = 0xe4; 
    packettests->mac.decmac[4]  = 0x00; 
    packettests->mac.decmac[5]  = 0x01;
 
     
   packettests->mac.srcmac[0]  =0x00;
   packettests->mac.srcmac[1] = 0x50;
   packettests->mac.srcmac[2] = 0x56;
   packettests->mac.srcmac[3] = 0xc0;
   packettests->mac.srcmac[4] = 0x00;
   packettests->mac.srcmac[5] = 0x01;


   packettests->mac.type=htons(0x0800);

  /*IP地址*/

   packettests->ip.ver_len=(4<<4)|5;
   packettests->ip.tos=0x00c0;
   packettests->ip.tlen=htons(sizeof(struct packettest)-sizeof(struct Etllernet));
   packettests->ip.identification= htons(17436);
   packettests->ip.flags_offset = htons((2<<13)|0);
   packettests->ip.ttl = 0x10;
   unsigned long src=inet_addr("2.2.2.2");
   unsigned long dec = inet_addr("1.1.1.1");
   packettests->ip.daddr=*((struct ip_address *)&dec);
   packettests->ip.saddr=*((struct ip_address *)&src);
    packettests->ip.proto=17;
	packettests->ip.crc=0;

	packettests->ip.crc=in_cksum((u_int16_t*)&packettests->ip,sizeof(struct ip_header));//crc_checksum((u_int16_t*)&(packettests->ip),sizeof(packettests->ip));
  


   //---------rip

    u_char *s= (u_char *)malloc(sizeof(struct packettest));
	memcpy(s,packettests,sizeof(struct packettest));
    memcpy(s+sizeof(struct Etllernet),&packettests->ip,sizeof(struct ip_header));
	//memcpy(s+sizeof(struct Etllernet)+(u_int)(packettests->ip.ver_len&0x0000000f)*4,&packettests->udp,sizeof(udp_header));
	
	dev_comm_forall = init_dev_comm();
	while(1)
	{
	cap_send(dev_comm_forall,s,sizeof(struct packettest));
	getchar();
	}
}


 //  packettests->rip.command=0x02;
 //  packettests->rip.ver=0x01;
 //  packettests->rip.zero=0;
 //   packettests->rip.ip=htons(2);
	//  packettests->rip.zero1=0;
	//unsigned long decss = inet_addr("2.0.0.0");
	//packettests->rip.ip1=*((struct ip_address *)&decss);
 //   packettests->rip.zero2=0;
 //   packettests->rip.zero3=0;
	//packettests->rip.metric1=htonl(1);

 //   


   //udp
//packettests->udp.sport=htons(520);
//packettests->udp.dport=htons(520);
//packettests->udp.len=htons(sizeof(struct packettest)-sizeof(struct Etllernet)-sizeof(struct ip_header)-2);
//packettests->udp.crc=0xf134;//crc_checksum((u_int16_t*)&(packettests->udp),sizeof(udp_header));
////========================================================================