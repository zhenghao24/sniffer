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
@synthesize Op_queue;
static AppDelegate *shared;

+(id)shared{
    if (!shared) {
        shared = [[AppDelegate alloc] init];
    }
    return shared;
}

-(id)init{
    if (shared) {
        return shared;
    }
    if(![super init])
        return nil;
    //Op_queue = [[NSOperationQueue alloc] init];
    shared = self;
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
