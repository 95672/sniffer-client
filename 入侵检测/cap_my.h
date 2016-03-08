

//0为错误代码，1为正确代码
extern int  cap_send(pcap_t *dev,u_char *packetdata,int len);
extern int base_cap();
extern pcap_t * init_dev_comm();
extern u_int16_t crc_checksum (u_int16_t *p, int psize);
extern void listen_base(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
extern int init_file();
//extern int com_file_ipsa(struct ip_address *ip);
extern pcap_t * init_dev_comm_name( pcap_if_t *dev_add);
extern int com_file_ipsa(struct ip_address *ip,struct ip_address *ips);
extern int init_file_ipt();
