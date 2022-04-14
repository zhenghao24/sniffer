//
//  AppDelegate.h
//  SnifferH
//
//  Created by 郑浩 on 2022/3/26.
//

#import <Cocoa/Cocoa.h>

@interface AppDelegate : NSObject <NSApplicationDelegate>{
    NSOperationQueue* Op_queue;
}
@property NSOperationQueue* Op_queue;
+(id)shared;


@end

