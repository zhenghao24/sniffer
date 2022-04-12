//
//  DisplayViewController.h
//  SnifferH
//
//  Created by 郑浩 on 2022/4/12.
//

#import <Cocoa/Cocoa.h>

NS_ASSUME_NONNULL_BEGIN

@interface DisplayViewController : NSViewController
@property (weak) IBOutlet NSTableView *PacketTableView;

- (NSInteger)numberOfRowsInTableView:(NSTableView*)tableView;
- (nullable id)tableView:(NSTableView *)tableView objectValueForTableColumn:(nullable NSTableColumn *)tableColumn row:(NSInteger)row;


@end

NS_ASSUME_NONNULL_END
