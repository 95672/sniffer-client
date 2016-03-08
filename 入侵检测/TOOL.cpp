
#include "def_cap.h"

/*IP地址校验和函数*/
u_int16_t crc_checksum (u_int16_t *p, int psize)
{
    u_int32_t ret = 0;
    while (psize > 1) 
    {
        ret += *p++;
        psize -= 2;
    }
    if (psize == 1)
      ret += *(u_int8_t*)p;
    ret = (ret >> 16) + (ret & 0xffff);
    ret += (ret >> 16);
    return ~ret;
}
///*CRC校验和函数*/
//u_int16_t crc_checksum(u_int16_t* p, int psize)
//{
//    u_int32_t ret = 0;
//    while (psize > 1) 
//    {
//        ret += *p++;
//        psize -= 2;
//    }
//    if (psize == 1)
//        ret += *(u_int8_t*)p;
//    ret = (ret >> 16) + (ret & 0xffff);
//    ret += (ret >> 16);
//    return ~ret;
//}

int comp_mac(u_int8_t decmac[],u_int8_t srcmac[])
{
	for(int n=0;n<sizeof(decmac);n++)
	{
	if(decmac[n]=srcmac[n])
		continue;
	else
		return 0;//0 就是不一样
	}
	return 1;
}
int comp_ip(struct ip_address* ipdec,struct ip_address* ipsrc)
{
	if(ipdec->byte1==ipsrc->byte1&&ipdec->byte2==ipsrc->byte2&&ipdec->byte3==ipsrc->byte3&&ipdec->byte4==ipsrc->byte4)
		return 1;
	else
		return 0;


}
