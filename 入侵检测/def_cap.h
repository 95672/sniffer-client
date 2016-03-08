#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif//兼容性问题预先定义

#include "pcap.h"
#include <pthread.h>
#include <malloc.h>
#include <Windows.h>
#pragma comment(lib, "ws2_32.lib")


/* IP地址 */
typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

/* IPv4 首部 */
typedef struct ip_header{
    u_int8_t  ver_len;        // 版本 (4 bits) + 首部长度 (4 bits)
    u_char  tos;            // 服务类型
    u_short tlen;           // 总长
    u_short identification; // 标识
    u_short flags_offset;       // 标志位 (3 bits) + 段偏移量(Fragment offset) (13 bits)
    u_char  ttl;            // 存活时间
    u_char  proto;          // 协议  tcp6  udp 17
    u_short crc;            // 首部校验和
    ip_address  saddr;      // 源地址
    ip_address  daddr;      // 目的地址
    u_int   op_pad;         // 选项与填充
}ip_header;

/* UDP 首部*/
typedef struct udp_header{
    u_short sport;          // 源端口
    u_short dport;          // 目的端口
    u_short len;            // UDP数据包长度
    u_short crc;            // 校验和
}udp_header;
/* MAC 首部*/
typedef struct Etllernet{
	u_int8_t decmac[6];//目标MAC
	u_int8_t srcmac[6];//源MAC
	u_int16_t type;//类型，0x0800是IP，0x0806是ARP
}Etllernet;


typedef struct ripv1
{
	u_char command;
	u_char ver;
	unsigned short int zero;//必须为0
	unsigned short int ip;
	unsigned short int zero1;//必须为0
    ip_address ip1;
	unsigned  int zero2;
	unsigned  int zero3;
	unsigned  int metric1;
}ripv1;

typedef struct header_tcp
{
    u_short src_port;
    u_short dst_port;
    u_int seq;
    u_int ack_seq;
    u_short doff:4,hlen:4,fin:1,syn:1,rst:1,psh:1,ack:1,urg:1,ece:1,cwr:1;
	u_short len_sav_bj;
    u_short window;
    u_short check;
    u_short urg_ptr;
}tcp_header;

typedef struct packettest{
	Etllernet mac;
	ip_header ip;
  // udp_header udp;
}packettest;


//=======================================================

typedef struct thread_fen
{
u_char *packet_data;
int th[50];
pthread_mutex_t lock;
}thread_fen;//这个是公共缓冲区的定义

typedef struct thread_in
{
int num;
ip_address ip_address;
}thread_in;//这个是传入线程的变量  分别是线程号码，以及相关的IP地址信息
typedef struct ipcomst
{
	ip_address ipsrc;
	ip_address ipdec;
}ipcomst;
//========================================================数据集内容
typedef struct conlist//发送给客户端的设备格式
{
	ip_address ipsrc;
	ip_address ipdec;
	u_char zero;
    int src_port;
	u_char zero1;
    int dst_port;
    int ip_pro;
    int fin;
	int syn;
	int rst;
	int ack;
	int seq;
	int ackseq;
	int tlen;
}conlists;


