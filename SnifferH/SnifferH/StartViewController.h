//
//  StartViewController.h
//  SnifferH
//
//  Created by 郑浩 on 2022/4/9.
//

#import <Cocoa/Cocoa.h>

NS_ASSUME_NONNULL_BEGIN

@interface StartViewController : NSViewController
@property (weak) IBOutlet NSTableView *NetDeviceTableView;
@property (weak) IBOutlet NSComboBoxCell *FilterBox;

- (NSInteger)numberOfRowsInTableView:(NSTableView*)tableView;
- (nullable id)tableView:(NSTableView *)tableView objectValueForTableColumn:(nullable NSTableColumn *)tableColumn row:(NSInteger)row;

@end

NS_ASSUME_NONNULL_END
