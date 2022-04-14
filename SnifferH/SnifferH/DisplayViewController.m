//
//  DisplayViewController.m
//  SnifferH
//
//  Created by 郑浩 on 2022/4/12.
//
#import <string.h>
#import <stdlib.h>
#import <pcap/pcap.h>
#import <netinet/in.h>
#import "DisplayViewController.h"
#import "sniffer.h"
#import "SniffOperation.h"

@interface DisplayViewController ()<NSTableViewDelegate, NSTableViewDataSource>

@end

@implementation DisplayViewController
static DisplayViewController *shared;
static int layer_nr;
static struct packet_record* sel_record;

+(id)shared{
    if (!shared) {
        shared = [[DisplayViewController alloc] init];
    }
    return shared;
}

-(id)init{
    
    shared = self;
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do view setup here.
    self.PacketTableView.delegate = self;
    self.PacketTableView.dataSource = self;
    self.ProtocolLayer.delegate = self;
    self.ProtocolLayer.dataSource = self;
    f_cnt = p_cnt;
    layer_nr = 0;
    sel_record = NULL;
    memcpy(f_records, p_records, f_cnt * sizeof(struct packet_record*));
    
}

- (NSInteger)numberOfRowsInTableView:(NSTableView*)tableView{
    if(![tableView.identifier compare:@"PacketTable"])
        return f_cnt;
    else{
        return layer_nr;
    }
}



- (IBAction)StartSniff:(id)sender {
    NSOperationQueue *queue = [[NSOperationQueue alloc] init];
    SniffOperation* sniff_op = [[SniffOperation alloc] initWithHandle:p_handle];
    [queue addOperation:sniff_op];

}

- (IBAction)StopSniff:(id)sender {
    pcap_breakloop(p_handle);
}

- (IBAction)DoTCPTrace:(id)sender {
    char* trace = (char*)[self.TCPTrace.stringValue UTF8String];
    char srcIP[INET_ADDRSTRLEN];
    char destIP[INET_ADDRSTRLEN];
    char srcPort_str[6];
    char destPort_str[6];
    uint16_t srcPort, destPort;
    int i, j;
    if(strlen(trace) == 0){
        //printf("tcp trace: %s\n", trace);
        return;
    }
    for(i = 0, j = 0; trace[i] != ' ' && i < INET_ADDRSTRLEN; i++, j++){
        srcIP[j] = trace[i];
    }
    srcIP[j] = '\0';
    for(i++, j = 0; trace[i] != ' ' && i < 2 * INET_ADDRSTRLEN; i++, j++){
        srcPort_str[j] = trace[i];
    }
    srcPort_str[j] = '\0';
    for(i++, j = 0; trace[i] != ' ' && i < 3 * INET_ADDRSTRLEN; i++, j++){
        destIP[j] = trace[i];
    }
    destIP[j] = '\0';
    for(i++, j = 0; trace[i] != '\0' && i < 4 * INET_ADDRSTRLEN; i++, j++){
        destPort_str[j] = trace[i];
    }
    destPort_str[j] = '\0';
    srcPort = (uint16_t)atoi(srcPort_str);
    destPort = (uint16_t)atoi(destPort_str);
    f_cnt = filter_tcp_stream(srcIP, destIP, srcPort, destPort);
    [self.PacketTableView reloadData];
}

- (IBAction)DisplayTLS:(id)sender {
    int tls_on, http_on, tcp_on, udp_on, icmp_on;
    tcp_on = (self.ButtonTCP.state == NSControlStateValueOn)? 1 : 0;
    udp_on = (self.ButtonUDP.state == NSControlStateValueOn)? 1 : 0;
    icmp_on = (self.ButtonICMP.state == NSControlStateValueOn)? 1 : 0;
    http_on = (self.ButtonHTTP.state == NSControlStateValueOn)? 1 : 0;
    tls_on = (self.ButtonTLS.state == NSControlStateValueOn)? 1 : 0;
    
    f_cnt = filter_protocol(tcp_on, udp_on, icmp_on, http_on, tls_on);
    [self.PacketTableView reloadData];
}

- (IBAction)DisplayHTTP:(id)sender {
    int tls_on, http_on, tcp_on, udp_on, icmp_on;
    tcp_on = (self.ButtonTCP.state == NSControlStateValueOn)? 1 : 0;
    udp_on = (self.ButtonUDP.state == NSControlStateValueOn)? 1 : 0;
    icmp_on = (self.ButtonICMP.state == NSControlStateValueOn)? 1 : 0;
    http_on = (self.ButtonHTTP.state == NSControlStateValueOn)? 1 : 0;
    tls_on = (self.ButtonTLS.state == NSControlStateValueOn)? 1 : 0;
    
    f_cnt = filter_protocol(tcp_on, udp_on, icmp_on, http_on, tls_on);
    [self.PacketTableView reloadData];
}

- (IBAction)DisplayICMP:(id)sender {
    int tls_on, http_on, tcp_on, udp_on, icmp_on;
    tcp_on = (self.ButtonTCP.state == NSControlStateValueOn)? 1 : 0;
    udp_on = (self.ButtonUDP.state == NSControlStateValueOn)? 1 : 0;
    icmp_on = (self.ButtonICMP.state == NSControlStateValueOn)? 1 : 0;
    http_on = (self.ButtonHTTP.state == NSControlStateValueOn)? 1 : 0;
    tls_on = (self.ButtonTLS.state == NSControlStateValueOn)? 1 : 0;
    
    f_cnt = filter_protocol(tcp_on, udp_on, icmp_on, http_on, tls_on);
    [self.PacketTableView reloadData];
}

- (IBAction)DisplayUDP:(id)sender {
    int tls_on, http_on, tcp_on, udp_on, icmp_on;
    tcp_on = (self.ButtonTCP.state == NSControlStateValueOn)? 1 : 0;
    udp_on = (self.ButtonUDP.state == NSControlStateValueOn)? 1 : 0;
    icmp_on = (self.ButtonICMP.state == NSControlStateValueOn)? 1 : 0;
    http_on = (self.ButtonHTTP.state == NSControlStateValueOn)? 1 : 0;
    tls_on = (self.ButtonTLS.state == NSControlStateValueOn)? 1 : 0;
    
    f_cnt = filter_protocol(tcp_on, udp_on, icmp_on, http_on, tls_on);
    [self.PacketTableView reloadData];
}

- (IBAction)DisplayTCP:(id)sender {
    int tls_on, http_on, tcp_on, udp_on, icmp_on;
    tcp_on = (self.ButtonTCP.state == NSControlStateValueOn)? 1 : 0;
    udp_on = (self.ButtonUDP.state == NSControlStateValueOn)? 1 : 0;
    icmp_on = (self.ButtonICMP.state == NSControlStateValueOn)? 1 : 0;
    http_on = (self.ButtonHTTP.state == NSControlStateValueOn)? 1 : 0;
    tls_on = (self.ButtonTLS.state == NSControlStateValueOn)? 1 : 0;
    
    f_cnt = filter_protocol(tcp_on, udp_on, icmp_on, http_on, tls_on);
    [self.PacketTableView reloadData];
    
}

- (IBAction)RefreshPacketTable:(id)sender {
    f_cnt = p_cnt;
    memcpy(f_records, p_records, f_cnt * sizeof(struct packet_record*));
    [self.PacketTableView reloadData];
}

- (nullable id)tableView:(NSTableView *)tableView objectValueForTableColumn:(nullable NSTableColumn *)tableColumn row:(NSInteger)row{
    

    if(![tableView.identifier compare:@"PacketTable"]){
        struct packet_record* record = f_records[row];
        
        if(![tableColumn.identifier compare:@"No"]){
            NSString* idx = [NSString stringWithFormat:@"%lu", record->idx];
            return idx;
        }
        else if(![tableColumn.identifier compare:@"Time"]){
            float time = (record->pcap_hdr.ts.tv_sec - initial_time.tv_sec) + (record->pcap_hdr.ts.tv_usec - initial_time.tv_usec)/ 1000000.0;
            NSString* time_str = [NSString stringWithFormat:@"%.4f s", time];
            return time_str;
        }
        else if(![tableColumn.identifier compare:@"Source"]){
            if(record->proto_type != PROTOCOL_ARP && record->proto_type != PROTOCOL_ETH){
                NSString* source = [[NSString alloc] initWithUTF8String:record->hdr_record.ip_record.sourceIP];
                return source;
            }
            else
                return nil;
            
        }
        else if(![tableColumn.identifier compare:@"Dest"]){
            if(record->proto_type != PROTOCOL_ARP && record->proto_type != PROTOCOL_ETH){
                NSString* dest = [[NSString alloc] initWithUTF8String:record->hdr_record.ip_record.destIP];
                return dest;
            }
            else
                return nil;
            
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
    else{//Protocol Layer
        if(sel_record == NULL)
            return nil;
        else{
            long row_t = row + 1;
            NSString* row_str;
            switch (row_t) {
                case 1:
                    row_str = [NSString stringWithFormat:@"Layer[1]:Physical Frame"];
                    break;
                case 2:
                    if(sel_record->layer_nr >= 2 && sel_record->proto_layer[2] == PROTOCOL_ETH)
                        row_str = [NSString stringWithFormat:@"Layer[2]: Ethernet II"];
                    else
                        row_str = [NSString stringWithFormat:@"Layer[2]: Unknown 2nd Layer Protocol"];
                    break;
                case 3:
                    if(sel_record->layer_nr >= 3 && sel_record->proto_layer[3] == PROTOCOL_ARP)
                        row_str = [NSString stringWithFormat:@"Layer[3]: Address Resolution Protocol"];
                    else if(sel_record->layer_nr >= 3 && sel_record->proto_layer[3] == PROTOCOL_IP)
                        row_str = [NSString stringWithFormat:@"Layer[3]: Internet Protocol Version 4"];
                    else
                        row_str = [NSString stringWithFormat:@"Layer[3]: Unknown 3rd Layer Protocol"];
                    break;
                case 4:
                    if(sel_record->layer_nr >= 4 && sel_record->proto_layer[4] == PROTOCOL_TCP)
                        row_str = [NSString stringWithFormat:@"Layer[4]: Transmission Control Protocol; SrcPort: %d; DestPort: %d", sel_record->hdr_record.tcp_record.sourcePort, sel_record->hdr_record.tcp_record.destPort];
                    else if(sel_record->layer_nr >= 4 && sel_record->proto_layer[4] == PROTOCOL_UDP)
                        row_str = [NSString stringWithFormat:@"Layer[4]: User Datagram Protocol; SrcPort: %d; DestPort: %d", sel_record->hdr_record.udp_record.sourcePort, sel_record->hdr_record.udp_record.destPort];
                    else if(sel_record->layer_nr >= 4 && sel_record->proto_layer[4] == PROTOCOL_ICMP)
                        row_str = [NSString stringWithFormat:@"Layer[4]: Internet Control Message Protocol"];
                    else
                        row_str = [NSString stringWithFormat:@"Layer[4]: Unknown 4th Layer Protocol"];
                    break;
                case 5:
                    if(sel_record->layer_nr >= 5 && sel_record->proto_layer[5] == PROTOCOL_HTTP)
                        row_str = [NSString stringWithFormat:@"Layer[5]: Hyper Text Transfer Protocol"];
                    else if(sel_record->layer_nr >= 5 && sel_record->proto_layer[5] == PROTOCOL_TLS)
                        row_str = [NSString stringWithFormat:@"Layer[5]: Transport Layer Security"];
                    else
                        row_str = [NSString stringWithFormat:@"Layer[5]: Unknown 5th Layer Protocol"];
                    break;
                    
                default:
                    return nil;
                
            }
            return row_str;
            
        }
        
    }
    
}

- (void)tableViewSelectionDidChange:(NSNotification *)notification {
    if(notification.object == self.PacketTableView && self.PacketTableView.selectedRow){
        char content[MAX_PACKET_LEN];
        struct packet_record* record = f_records[self.PacketTableView.selectedRow];
        TransContent(record->packet, content, record->pcap_hdr.caplen);
        self.RawPacketContent.string = [NSString stringWithUTF8String:content];
        sel_record = record;
        layer_nr = sel_record->layer_nr;
        [self.ProtocolLayer reloadData];
    }
}
@end
