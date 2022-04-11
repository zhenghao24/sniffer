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
//#import <netinet/ether.h>
#import <arpa/inet.h>


#import <Foundation/Foundation.h>

#import "sniffer.h"

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


void getNetDevices(void){
    char errbuf[PCAP_ERRBUF_SIZE];
    
    pcap_if_t *alldev, *dev;
    
    printf("[+] scanning for devices...");
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
    dev_cnt = idx;
}


void sniffer_pcap_handler(u_char *user_arg, const struct pcap_pkthdr *pkthdr, const u_char *packet){
    
}
void ip_handler(char* packet, uint64_t len){
    
}
