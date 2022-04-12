//
//  AppDelegate.m
//  SnifferH
//
//  Created by 郑浩 on 2022/3/26.
//

#import "AppDelegate.h"

@interface AppDelegate ()


@end

@implementation AppDelegate

-(id)init{
    if(![super init])
        return nil;
    Op_queue = [[NSOperationQueue alloc] init];
    
    return self;
}

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification {
    // Insert code here to initialize your application
    
}


- (void)applicationWillTerminate:(NSNotification *)aNotification {
    // Insert code here to tear down your application
}


- (BOOL)applicationSupportsSecureRestorableState:(NSApplication *)app {
    return YES;
}


@end
