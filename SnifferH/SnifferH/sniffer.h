//
//  sniffer.h
//  SnifferH
//
//  Created by 郑浩 on 2022/4/11.
//

//#ifndef sniffer_h
//#define sniffer_h
//#endif /* sniffer_h */


#import <stdlib.h>
#import <pcap/pcap.h>
#import <netinet/in.h>


#define MAX_SNIFF_PACKET_NR 100000
#define MAX_SNIFF_DEVICE_NR 10

//sniffer支持的网络协议类型
enum protocol_type{
  PROTOCOL_ETH=1,
  PROTOCOL_IP,
  PROTOCOL_ARP,
  PROTOCOL_ICMP,
  PROTOCOL_TCP,
  PROTOCOL_UDP,
  PROTOCOL_HTTP,
  PROTOCOL_TLS
};

//记录数据包的IP二元组：源IP和目的IP
struct ip_record{
  char sourceIP[INET_ADDRSTRLEN];   //#define INET_ADDRSTRLEN 16 /* for IPv4 dotted-decimal */
  char destIP[INET_ADDRSTRLEN];
};

//记录TCP/IP数据包的报文首部信息
struct tcp_record{
  struct ip_record ip_record;
  uint16_t sourcePort;
  uint16_t destPort;
  uint8_t flag_syn;
  uint8_t flag_ack;
  uint8_t flag_fin;
  uint32_t seq;
  uint32_t ack;
};

//记录UDP/IP数据包的报文首部信息
struct udp_record{
  struct ip_record ip_record;
  uint16_t sourcePort;
  uint16_t destPort;
};


//记录每一个被捕获数据包的相关信息
struct packet_record{
  unsigned long idx;            //被捕获的序号
  enum protocol_type proto_type;      //数据包的协议类型
  union record{
    struct ip_record ip_record;     //ICMP等
    struct tcp_record tcp_record;   //TCP类
    struct udp_record udp_record;   //UDP类
  } hdr_record;                     //数据包首部信息记录
  struct pcap_pkthdr pcap_hdr;      //pcap packet header
  char* packet;                     //数据包地址
};
/*
struct pcap_pkthdr {
    struct timeval ts;    // time stamp
    bpf_u_int32 caplen;    // length of portion present
    bpf_u_int32 len;    // length this packet (off wire)
#ifdef __APPLE__
    char comment[256];
#endif
};
*/

//Global variables
extern unsigned long p_cnt;        //记录当前捕捉到的数据包总数
extern struct packet_record* p_records[MAX_SNIFF_PACKET_NR]; //当前捕捉到的数据包的record数组
extern unsigned char dev_cnt;                      //sniffer可用的网络设备数
extern char netdevices[MAX_SNIFF_DEVICE_NR][100]; //sniffer可用的网络设备数组

//Functions

//获取sniffer可用的所有网络设备，将网络设备总数记录到dev_cnt中，将网络设备名记录到netdevices数组中
void getNetDevices(void);

void sniffer_pcap_handler(u_char *user_arg, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void ip_handler(char* packet, uint64_t len);



