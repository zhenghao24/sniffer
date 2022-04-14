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
//#import "Darwin.net.bpf"


@implementation SniffOperation
@synthesize device;
@synthesize filter;
@synthesize handle;


-(id)initWithDevice:(char *)device andFilter: (char*)filter{
    if(![super init])
        return nil;
    self.device = device;
    self.filter = filter;
    self.handle = NULL;
    return self;
}
-(id)initWithHandle:(pcap_t*)handle{
    self.handle = handle;
    return self;
}
    

-(void)main{
    if(self.handle == NULL){
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_create(device, errbuf);
        if(!handle) printf("[-] open device:%s failed %s\n", device, errbuf);
        
        if(pcap_set_snaplen(handle, 65530)) printf("[-] error when setting snaplen: %s\n", pcap_geterr(handle));
        if(pcap_set_promisc(handle, 1)) printf("[-] error when setting promisc: %s\n", pcap_geterr(handle));
        if(pcap_set_timeout(handle, 0)) printf("[-] error when setting timeout: %s\n", pcap_geterr(handle));
        pcap_set_immediate_mode(handle, 1);
        pcap_activate(handle);
        //printf("%lu",(unsigned long)handle);
        //pcap_t* handle = pcap_open_live(device, 65530, 1, 0, errbuf);
        struct bpf_program filter_p;
        //printf("\nfilter: %s\n", filter);
        pcap_compile(handle, &filter_p, filter, 1, 0);
        pcap_setfilter(handle, &filter_p);
        p_handle = handle;
        
        if(pcap_loop(handle, -1, sniffer_pcap_handler, NULL))
            printf("[-] sniffing error: %s\n", pcap_geterr(handle));
    }
    else{
        if(pcap_loop(self.handle, -1, sniffer_pcap_handler, NULL))
            printf("[-] sniffing error: %s\n", pcap_geterr(self.handle));
    }
    
}
@end
