//
//  DisplayViewController.m
//  SnifferH
//
//  Created by 郑浩 on 2022/4/12.
//

#import "DisplayViewController.h"
#import "sniffer.h"

@interface DisplayViewController ()<NSTableViewDelegate, NSTableViewDataSource>

@end

@implementation DisplayViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do view setup here.
    self.PacketTableView.delegate = self;
    self.PacketTableView.dataSource = self;
}

- (NSInteger)numberOfRowsInTableView:(NSTableView*)tableView{
    return p_cnt;
}

- (nullable id)tableView:(NSTableView *)tableView objectValueForTableColumn:(nullable NSTableColumn *)tableColumn row:(NSInteger)row{
    struct packet_record* record = p_records[row];
    
    if(![tableColumn.identifier compare:@"No"]){
        NSString* idx = [NSString stringWithFormat:@"%lu", record->idx];
        return idx;
    }
    else if(![tableColumn.identifier compare:@"Time"]){
        float time = record->pcap_hdr.ts.tv_sec + record->pcap_hdr.ts.tv_usec / 1000000.0;
        NSString* time_str = [NSString stringWithFormat:@"%.4f", time];
        return time_str;
    }
    else if(![tableColumn.identifier compare:@"Source"]){
        NSString* source = [[NSString alloc] initWithUTF8String:record->hdr_record.ip_record.sourceIP];
        return source;
        
    }
    else if(![tableColumn.identifier compare:@"Dest"]){
        NSString* dest = [[NSString alloc] initWithUTF8String:record->hdr_record.ip_record.destIP];
        return dest;
        
    }
    else if(![tableColumn.identifier compare:@"Protocol"]){
        NSString* protocol;
        switch (record->proto_type) {
            case PROTOCOL_ETH:
                protocol = @"ETHERNET";
                break;
            case PROTOCOL_ARP:
                protocol = @"ARP";
                break;
            case PROTOCOL_IP:
                protocol = @"IP";
                break;
            case PROTOCOL_TCP:
                protocol = @"TCP";
                break;
            case PROTOCOL_UDP:
                protocol = @"UDP";
                break;
            case PROTOCOL_ICMP:
                protocol = @"ICMP";
                break;
            case PROTOCOL_HTTP:
                protocol = @"HTTP";
                break;
            case PROTOCOL_TLS:
                protocol = @"TLS";
                break;
            default:
                protocol = @"Unknown";
                break;
        }
        return protocol;
        
    }
    else if(![tableColumn.identifier compare:@"Length"]){
        NSString* len = [NSString stringWithFormat:@"%d", record->pcap_hdr.caplen];
        return len;
    }
    else{
        return nil;
    }
    
}

@end
