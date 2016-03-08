#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif//����������Ԥ�ȶ���

#include "pcap.h"
#include <pthread.h>
#include <malloc.h>
#include <Windows.h>
#pragma comment(lib, "ws2_32.lib")


/* IP��ַ */
typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

/* IPv4 �ײ� */
typedef struct ip_header{
    u_int8_t  ver_len;        // �汾 (4 bits) + �ײ����� (4 bits)
    u_char  tos;            // ��������
    u_short tlen;           // �ܳ�
    u_short identification; // ��ʶ
    u_short flags_offset;       // ��־λ (3 bits) + ��ƫ����(Fragment offset) (13 bits)
    u_char  ttl;            // ���ʱ��
    u_char  proto;          // Э��  tcp6  udp 17
    u_short crc;            // �ײ�У���
    ip_address  saddr;      // Դ��ַ
    ip_address  daddr;      // Ŀ�ĵ�ַ
    u_int   op_pad;         // ѡ�������
}ip_header;

/* UDP �ײ�*/
typedef struct udp_header{
    u_short sport;          // Դ�˿�
    u_short dport;          // Ŀ�Ķ˿�
    u_short len;            // UDP���ݰ�����
    u_short crc;            // У���
}udp_header;
/* MAC �ײ�*/
typedef struct Etllernet{
	u_int8_t decmac[6];//Ŀ��MAC
	u_int8_t srcmac[6];//ԴMAC
	u_int16_t type;//���ͣ�0x0800��IP��0x0806��ARP
}Etllernet;


typedef struct ripv1
{
	u_char command;
	u_char ver;
	unsigned short int zero;//����Ϊ0
	unsigned short int ip;
	unsigned short int zero1;//����Ϊ0
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
}thread_fen;//����ǹ����������Ķ���

typedef struct thread_in
{
int num;
ip_address ip_address;
}thread_in;//����Ǵ����̵߳ı���  �ֱ����̺߳��룬�Լ���ص�IP��ַ��Ϣ
typedef struct ipcomst
{
	ip_address ipsrc;
	ip_address ipdec;
}ipcomst;
//========================================================���ݼ�����
typedef struct conlist//���͸��ͻ��˵��豸��ʽ
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


