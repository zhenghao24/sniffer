//
//  SniffOperation.h
//  SnifferH
//
//  Created by 郑浩 on 2022/4/12.
//

#import <Foundation/Foundation.h>
#import <pcap/pcap.h>

NS_ASSUME_NONNULL_BEGIN

@interface SniffOperation : NSOperation{
    char* device;
    char* filter;
    pcap_t* handle;
    
}
@property (readwrite) char* device;
@property (readwrite) char* filter;
@property (readwrite) pcap_t* handle;

-(id)initWithDevice:(char*)device andFilter:(char*)filter;
-(id)initWithHandle:(pcap_t*)handle;
@end

NS_ASSUME_NONNULL_END
