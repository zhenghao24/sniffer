//
//  StartViewController.m
//  SnifferH
//
//  Created by 郑浩 on 2022/4/9.
//
#import "AppDelegate.h"
#import "StartViewController.h"
#import "SniffOperation.h"
#import "sniffer.h"


@interface StartViewController ()<NSTableViewDelegate,NSTableViewDataSource>

@end

@implementation StartViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do view setup here.
    
    self.NetDeviceTableView.delegate = self;
    self.NetDeviceTableView.dataSource = self;
    getNetDevices();

    
}

- (NSInteger)numberOfRowsInTableView:(NSTableView*)tableView{
    return dev_cnt;
}


- (nullable id)tableView:(NSTableView *)tableView objectValueForTableColumn:(nullable NSTableColumn *)tableColumn row:(NSInteger)row{
    NSString *dev_string = [[NSString alloc] initWithUTF8String:netdevices[row]];
    return dev_string;
}

- (void)prepareForSegue:(NSStoryboardSegue *)segue sender:(id)sender{
    NSOperationQueue *queue = [[NSOperationQueue alloc] init];
    char* dev = netdevices[self.NetDeviceTableView.selectedRow];
    char* filter = (char*)[self.FilterBox.stringValue UTF8String];
    SniffOperation* sniff_op = [[SniffOperation alloc] initWithDevice:dev andFilter:filter];
    [queue addOperation:sniff_op];
}
@end
