//
//  SniffOperation.m
//  SnifferH
//
//  Created by 郑浩 on 2022/4/12.
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

#import "SniffOperation.h"
#import "sniffer.h"


@implementation SniffOperation
@synthesize device;

-(id)initWithDevice:(char *)device{
    if(![super init])
        return nil;
    self.device = device;
    return self;
}


-(void)main{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap_handle = pcap_open_live(self.device, 65530, 1, 0, errbuf);
    if(pcap_loop(pcap_handle, -1, sniffer_pcap_handler, NULL))
        printf("[-] sniffing error: %s\n", pcap_geterr(pcap_handle));
    
}

@end
