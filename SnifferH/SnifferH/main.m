//
//  main.m
//  SnifferH
//
//  Created by 郑浩 on 2022/3/26.
//

#import <Cocoa/Cocoa.h>

#import "sniffer.h"

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        // Setup code that might create autoreleased objects goes here.
    }
    getNetDevices();
    
    
    return NSApplicationMain(argc, argv);
}
