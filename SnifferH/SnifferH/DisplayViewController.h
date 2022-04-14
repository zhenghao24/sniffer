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
@property (weak) IBOutlet NSTableView *ProtocolLayer;

@property (unsafe_unretained) IBOutlet NSTextView *RawPacketContent;

@property (weak) IBOutlet NSButton *ButtonTCP;
@property (weak) IBOutlet NSButton *ButtonUDP;
@property (weak) IBOutlet NSButton *ButtonICMP;
@property (weak) IBOutlet NSButton *ButtonHTTP;
@property (weak) IBOutlet NSButton *ButtonTLS;


@property (weak) IBOutlet NSTextField *TCPTrace;


+(id)shared;
-(id)init;
- (NSInteger)numberOfRowsInTableView:(NSTableView*)tableView;
- (nullable id)tableView:(NSTableView *)tableView objectValueForTableColumn:(nullable NSTableColumn *)tableColumn row:(NSInteger)row;
- (IBAction)RefreshPacketTable:(id)sender;
- (IBAction)DisplayTCP:(id)sender;
- (IBAction)DisplayUDP:(id)sender;
- (IBAction)DisplayICMP:(id)sender;
- (IBAction)DisplayHTTP:(id)sender;

- (IBAction)DisplayTLS:(id)sender;
- (IBAction)DoTCPTrace:(id)sender;
- (IBAction)StopSniff:(id)sender;
- (IBAction)StartSniff:(id)sender;


@end

NS_ASSUME_NONNULL_END
