//
//  StartViewController.m
//  SnifferH
//
//  Created by 郑浩 on 2022/4/9.
//

#import "StartViewController.h"
#import "sniffer.h"


@interface StartViewController ()<NSTableViewDelegate,NSTableViewDataSource>

@end

@implementation StartViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do view setup here.
    
    self.NetDeviceTableView.delegate = self;
    self.NetDeviceTableView.dataSource = self;
    
    
}

- (NSInteger)numberOfRowsInTableView:(NSTableView*)tableView{
    return dev_cnt;
}

- (nullable id)tableView:(NSTableView *)tableView objectValueForTableColumn:(nullable NSTableColumn *)tableColumn row:(NSInteger)row{
    NSString *dev_string = [[NSString alloc] initWithUTF8String:netdevices[row]];
    return dev_string;
}


@end
