//
//  sniffer.m
//  SnifferH
//
//  Created by 郑浩 on 2022/4/11.
//


#import <stdio.h>
#import <stdlib.h>
#import <string.h>
#import <unistd.h>
#import <pcap/pcap.h>
#import <net/ethernet.h>
#import <netinet/in.h>
#import <netinet/ip.h>
#import <netinet/tcp.h>
#import <netinet/udp.h>
#import <arpa/inet.h>


#import <Foundation/Foundation.h>

#import "sniffer.h"
#import "DisplayViewController.h"

/*
 struct pcap_if {
     struct pcap_if *next;
     char *name;        // name to hand to "pcap_open_live()"
     char *description;    // textual description of interface, or NULL
     struct pcap_addr *addresses;
     bpf_u_int32 flags;    // PCAP_IF_ interface flags
 };
*/

unsigned long p_cnt;        //记录当前捕捉到的数据包总数
struct packet_record* p_records[MAX_SNIFF_PACKET_NR]; //当前捕捉到的数据包的record数组
unsigned char dev_cnt;                      //sniffer可用的网络设备数
char netdevices[MAX_SNIFF_DEVICE_NR][100]; //sniffer可用的网络设备数组
//char* filter_rules[MAX_FILTER_RULE_NR];
struct timeval initial_time;    //记录捕获第一个数据包的时间
struct packet_record* f_records[MAX_SNIFF_PACKET_NR];
unsigned long f_cnt;        //记录筛选后的数据包总数
pcap_t* p_handle;       //pcap handle
/*
void init_filter(void){
    filter_rules[0] = "ip";
    filter_rules[1] = "tcp";
    filter_rules[2] = "udp";
    //filter_rules[3] = "icmp";
    
}
*/
void getNetDevices(void){
    char errbuf[PCAP_ERRBUF_SIZE];
    
    pcap_if_t *alldev, *dev;
    
    printf("[+] scanning for devices...\n");
    if(pcap_findalldevs(&alldev, errbuf)){
        printf("[-] scanning device error: %s\n", errbuf);
        exit(1);
    }
    printf("done\n");
    int idx = 0;
    for(dev = alldev; dev != NULL; dev = dev->next){
        if(dev->name) strcpy(netdevices[idx], dev->name);
        printf("\t[ %d ] %s - %s\n", idx, dev->name, dev->description);
        idx++;
    }
    printf("\ndev_cnt: %d\n", idx);
    dev_cnt = idx;
}


void sniffer_pcap_handler(u_char *user_arg, const struct pcap_pkthdr *pkthdr, const u_char *packet){
    
    uint32_t len = pkthdr->caplen;
    const u_char* packet_n = packet + 14;
    uint32_t len_n = len - 14;
    struct ether_header* eth_hdr = (struct ether_header*)packet;
    
    if(p_cnt == 0){
        initial_time.tv_sec = pkthdr->ts.tv_sec;
        initial_time.tv_usec = pkthdr->ts.tv_usec;
    }
    
    //record info
    p_records[p_cnt] = malloc(sizeof(struct packet_record) + len);
    memcpy(&p_records[p_cnt]->pcap_hdr, pkthdr, sizeof(struct pcap_pkthdr));
    memcpy(&p_records[p_cnt]->packet, packet, len);
    p_records[p_cnt]->idx = p_cnt;
    p_records[p_cnt]->proto_type = PROTOCOL_ETH;
    p_records[p_cnt]->proto_layer[2] = PROTOCOL_ETH;
    p_records[p_cnt]->layer_nr = 2;
    
    //to next layer
    switch(ntohs(eth_hdr->ether_type)){
        case ETHERTYPE_ARP:
            arp_handler(packet_n, len_n);
            break;
        case ETHERTYPE_IP:
            ip_handler(packet_n, len_n);
            break;
        default:
            printf("unknown 3rd layer packet captured\n");
    }
    //p_cnt更新
    p_cnt++;
    printf("pcnt:%lu\n", p_cnt);
    //[[[DisplayViewController shared] PacketTableView] reloadData];
}

void arp_handler(const u_char* packet, uint32_t len){
    p_records[p_cnt]->proto_type = PROTOCOL_ARP;
    p_records[p_cnt]->proto_layer[3] = PROTOCOL_ARP;
    p_records[p_cnt]->layer_nr += 1;
}


void ip_handler(const u_char* packet, uint32_t len){
    const struct ip* ip_hdr = (struct ip*)packet;
    uint32_t ip_hdr_len = (*(uint32_t*)ip_hdr & 0x0f) * 4;
    const u_char* ip_payload = packet + ip_hdr_len;
    uint32_t ip_payload_len = len - ip_hdr_len;

    //record info
    inet_ntop(AF_INET, &(ip_hdr->ip_src), p_records[p_cnt]->hdr_record.ip_record.sourceIP, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_hdr->ip_dst), p_records[p_cnt]->hdr_record.ip_record.destIP, INET_ADDRSTRLEN);
    p_records[p_cnt]->proto_type = PROTOCOL_IP;
    p_records[p_cnt]->proto_layer[3] = PROTOCOL_IP;
    p_records[p_cnt]->layer_nr += 1;

    //to next layer
    switch(ip_hdr->ip_p){
        case IPPROTO_TCP:
            tcp_handler(ip_payload, ip_payload_len);
            break;
        case IPPROTO_UDP:
            udp_handler(ip_payload, ip_payload_len);
            break;
        case IPPROTO_ICMP:
            icmp_handler(ip_payload, ip_payload_len);
            break;
        default:
            //printf("unknown 4rd layer packet captured\n");
            break;
    }
    
}


void tcp_handler(const u_char* packet, uint32_t len){
    struct tcphdr* tcp_hdr = (struct tcphdr*)packet;
    uint8_t tcp_hdr_len = ((*(uint8_t*)(packet + 12) & 0xF0) >> 4) * 4;
    //uint8_t tcp_hdr_len = tcp_hdr->th_off * 4;
    const u_char* payload = packet + tcp_hdr_len;
    uint32_t payload_len = len - tcp_hdr_len;
    
    uint16_t sourcePort, destPort;
    sourcePort = ntohs(tcp_hdr->th_sport);
    destPort = ntohs(tcp_hdr->th_dport);
      
    //record info
    p_records[p_cnt]->hdr_record.tcp_record.sourcePort = sourcePort;
    p_records[p_cnt]->hdr_record.tcp_record.destPort = destPort;
    p_records[p_cnt]->hdr_record.tcp_record.seq = ntohl(tcp_hdr->th_seq);
    p_records[p_cnt]->hdr_record.tcp_record.ack = ntohl(tcp_hdr->th_ack);

    p_records[p_cnt]->hdr_record.tcp_record.flag_syn = (tcp_hdr->th_flags & TH_SYN)? 1 : 0;
    p_records[p_cnt]->hdr_record.tcp_record.flag_ack = (tcp_hdr->th_flags & TH_ACK)? 1 : 0;
    p_records[p_cnt]->hdr_record.tcp_record.flag_fin = (tcp_hdr->th_flags & TH_FIN)? 1 : 0;
      
      
    p_records[p_cnt]->proto_type = PROTOCOL_TCP;
    p_records[p_cnt]->proto_layer[4] = PROTOCOL_TCP;
    p_records[p_cnt]->layer_nr += 1;

    //to next layer
    if(sourcePort == 80 || destPort == 80){
        http_handler(payload, payload_len);
    }
    else if(sourcePort == 443 || destPort == 443){
        tls_handler(payload, payload_len);
    }
    else{
        ;
    }
    
}
void udp_handler(const u_char* packet, uint32_t len){
    struct udphdr* udp_hdr = (struct udphdr*)packet;
    p_records[p_cnt]->hdr_record.udp_record.sourcePort = ntohs(udp_hdr->uh_sport);
    p_records[p_cnt]->hdr_record.udp_record.destPort = ntohs(udp_hdr->uh_dport);
    p_records[p_cnt]->proto_type = PROTOCOL_UDP;
    p_records[p_cnt]->proto_layer[4] = PROTOCOL_UDP;
    p_records[p_cnt]->layer_nr += 1;
    
}
void icmp_handler(const u_char* packet, uint32_t len){
    p_records[p_cnt]->proto_type = PROTOCOL_ICMP;
    p_records[p_cnt]->proto_layer[4] = PROTOCOL_ICMP;
    p_records[p_cnt]->layer_nr += 1;
}

void http_handler(const u_char* packet, uint32_t len){
    int layer = p_records[p_cnt]->layer_nr + 1;
    p_records[p_cnt]->proto_type = PROTOCOL_HTTP;
    p_records[p_cnt]->proto_layer[layer] = PROTOCOL_HTTP;
    p_records[p_cnt]->layer_nr += 1;
}
void tls_handler(const u_char* packet, uint32_t len){
    p_records[p_cnt]->proto_type = PROTOCOL_TLS;
    p_records[p_cnt]->proto_layer[5] = PROTOCOL_TLS;
    p_records[p_cnt]->layer_nr += 1;
}


void TransContent(char* raw, char* trans, uint32_t len){
    int i;
    for(i = 0; i < len; i++){
        if(raw[i] >= 32 && raw[i] <= 127)
            trans[i] = raw[i];
        else
            trans[i] = '.';
    }
    trans[i] = '\0';
}

void show_packet_content(uint64_t idx){
    if(idx >= MAX_SNIFF_PACKET_NR){
        printf("[-] packet index out of range\n");
        return;
    }
    
    char* packet = p_records[idx]->packet;
    uint32_t len = p_records[idx]->pcap_hdr.caplen;
    
    printf("packet[%llu]:\n", idx);
    for(uint32_t i=0; i < len; i++){
        if(packet[i] > 32 && packet[i] < 127){
          printf("%c", packet[i]);
        }
        else{
          printf(".");
        }
    }
    printf("\n");
}


unsigned long filter_protocol(int tcp_on, int udp_on, int icmp_on, int http_on, int tls_on){
    unsigned long cntf, cntp;
    for(cntf = 0, cntp = 0; cntp < p_cnt; cntp++){
        switch (p_records[cntp]->proto_type) {
            case PROTOCOL_TCP:
                if(tcp_on){
                    f_records[cntf++] = p_records[cntp];
                }
                break;
            case PROTOCOL_UDP:
                if(udp_on){
                    f_records[cntf++] = p_records[cntp];
                }
                break;
            case PROTOCOL_ICMP:
                if(icmp_on){
                    f_records[cntf++] = p_records[cntp];
                }
                break;
            case PROTOCOL_HTTP:
                if(http_on){
                    f_records[cntf++] = p_records[cntp];
                }
                break;
            case PROTOCOL_TLS:
                if(tls_on){
                    f_records[cntf++] = p_records[cntp];
                }
                break;
            default:
                break;
        }
    }
    return cntf;
    
}
unsigned long filter_tcp_stream(char* srcIP, char* destIP, uint16_t srcPort, uint16_t destPort){
    unsigned long cntf, cntp;
    struct packet_record* record;
    for(cntf = 0, cntp = 0; cntp < p_cnt; cntp++){
        record = p_records[cntp];
        if(record->proto_type == PROTOCOL_TCP || record->proto_type == PROTOCOL_HTTP || record->proto_type == PROTOCOL_TLS){
            if(!strcmp(srcIP, record->hdr_record.ip_record.sourceIP) && srcPort == record->hdr_record.tcp_record.sourcePort && !strcmp(destIP, record->hdr_record.ip_record.destIP) && destPort == record->hdr_record.tcp_record.destPort){
                f_records[cntf++] = record;
            }
            else if(!strcmp(srcIP, record->hdr_record.ip_record.destIP) && srcPort == record->hdr_record.tcp_record.destPort && !strcmp(destIP, record->hdr_record.ip_record.sourceIP) && destPort == record->hdr_record.tcp_record.sourcePort){
                f_records[cntf++] = record;
            }
        }
    }
    return cntf;
    
}
