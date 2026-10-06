#import <Foundation/Foundation.h>

@interface IPRedirectProtocol : NSURLProtocol <NSURLSessionDelegate, NSURLSessionTaskDelegate, NSURLSessionDataDelegate>
@end

@interface IPRedirector : NSObject
+ (void)setupRedirector;
@end
