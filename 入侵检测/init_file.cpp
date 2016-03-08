#include "def_cap.h"
#include "main_var.h"
int init_file_ipt();

int com_file_ipsa(struct ip_address *ip,struct ip_address *ips)
{
	
	for(int i=0;i<ip_save_num;i++)
	{
		if(ip->byte1==ipfile[i].ipdec.byte1||ip->byte1==ipfile[i].ipsrc.byte1)
			if(ip->byte2==ipfile[i].ipdec.byte2||ip->byte1==ipfile[i].ipsrc.byte2)
				if(ip->byte3==ipfile[i].ipdec.byte3||ip->byte1==ipfile[i].ipsrc.byte3)
					if(ip->byte4==ipfile[i].ipdec.byte4||ip->byte1==ipfile[i].ipsrc.byte4)
					{
						if(ips->byte1==ipfile[i].ipdec.byte1||ips->byte1==ipfile[i].ipsrc.byte1)
							if(ips->byte2==ipfile[i].ipdec.byte2||ips->byte2==ipfile[i].ipsrc.byte2)
								if(ips->byte3==ipfile[i].ipdec.byte3||ips->byte3==ipfile[i].ipsrc.byte3)
									if(ips->byte4==ipfile[i].ipdec.byte4||ips->byte4==ipfile[i].ipsrc.byte4)
									{
										
										return 0;
									
									}
					}
	}
	
	FILE *ip_add_save;
	ip_add_save = fopen("C:\\winpcap_dump\\ip.add_save_tcpcon.txt","a+");
	
	fprintf(ip_add_save,"%c.%c.%c.%c-%c.%c.%c.%c\n",ip->byte1,ip->byte2,ip->byte3,ip->byte4,ips->byte1,ips->byte2,ips->byte3,ips->byte4);
	fclose(ip_add_save);
	
	init_file_ipt();
	  return 1;//符合,就是说都不存在
}


int init_file_ipt()
{
	FILE *ip_add_save;
	ip_add_save = fopen("C:\\winpcap_dump\\ip.add_save_tcpcon.txt","a+");
		ip_save_num =0;
	int savenum=0;
	u_char b1,b2,b3,b4;
	u_char a1,a2,a3,a4;
	while(EOF!=fscanf(ip_add_save,"%c.%c.%c.%c-%c.%c.%c.%c\n",&b1,&b2,&b3,&b4,&a1,&a2,&a3,&a4))//格式为地址1----地址2
	{
	
		ipfile[ip_save_num].ipsrc.byte1 = a1;
		ipfile[ip_save_num].ipsrc.byte2 = a2;
		ipfile[ip_save_num].ipsrc.byte3 = a3;
		ipfile[ip_save_num].ipsrc.byte4 = a4;

		ipfile[ip_save_num].ipdec.byte1 = b1;
		ipfile[ip_save_num].ipdec.byte2 = b2;
		ipfile[ip_save_num].ipdec.byte3 = b3;
		ipfile[ip_save_num].ipdec.byte4 = b4;
	   
		//printf("===>%d.%d.%d.%d %d.%d.%d.%d\n",a1,a2,a3,a4,b1,b2,b3,b4);

	ip_save_num=ip_save_num+1;
	savenum=savenum+1;
	}

	
	fclose(ip_add_save);
	return 0;
}













	//if(ip->byte1==ipfile[i].ipdec.byte1)	
		//	if(ip->byte2==ipfile[i].ipdec.byte2)
		//		 if(ip->byte3==ipfile[i].ipdec.byte3)
		//			if(ip->byte4==ipfile[i].ipdec.byte4)
		//				if(ips->byte1==ipfile[i].ipsrc.byte4)
		//					if(ips->byte2==ipfile[i].ipsrc.byte2)
		//						if(ips->byte3==ipfile[i].ipsrc.byte3)
		//							if(ips->byte4==ipfile[i].ipsrc.byte4)
		//                     return 0;
		//
	 //if(ips->byte1==ipfile[i].ipdec.byte1)
		//  if(ips->byte2==ipfile[i].ipdec.byte2)
		//		 if(ips->byte3==ipfile[i].ipdec.byte3)
		//			if(ips->byte4==ipfile[i].ipdec.byte4)
		//				if(ip->byte1==ipfile[i].ipsrc.byte4)
		//					if(ip->byte2==ipfile[i].ipsrc.byte2)
		//						if(ip->byte3==ipfile[i].ipsrc.byte3)
		//							if(ip->byte4==ipfile[i].ipsrc.byte4)
		//								return 0;
		//
			  
