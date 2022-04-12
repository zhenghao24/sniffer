//
//  SniffOperation.h
//  SnifferH
//
//  Created by 郑浩 on 2022/4/12.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface SniffOperation : NSOperation{
    char* device;
}
@property (readwrite, atomic) char* device;
-(id)initWithDevice:(char*)device;
@end

NS_ASSUME_NONNULL_END
