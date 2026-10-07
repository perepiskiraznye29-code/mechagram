#import "IPRedirector.h"
#import "Config.h"
#import <objc/runtime.h>

static NSString *const kIPRedirectProtocolHandledKey =
    @"kIPRedirectProtocolHandledKey";

@implementation IPRedirectProtocol {
    NSURLSessionDataTask *_dataTask;
}

+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    if ([NSURLProtocol propertyForKey:kIPRedirectProtocolHandledKey
                            inRequest:request]) {
        return NO;
    }

    NSString *scheme = request.URL.scheme.lowercaseString;

    if (![scheme isEqualToString:@"http"] &&
        ![scheme isEqualToString:@"https"]) {
        return NO;
    }

    NSString *host = request.URL.host;

    if (!host || [host isEqualToString:TARGET_IP]) {
        return NO;
    }

    if (REDIRECT_ALL_HTTP) {
        return YES;
    }

    for (NSString *targetHost in TARGET_HOSTS_TO_REPLACE) {
        if ([host caseInsensitiveCompare:targetHost] == NSOrderedSame) {
            return YES;
        }
    }

    return NO;
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request {
    NSMutableURLRequest *req = [request mutableCopy];

    NSURLComponents *components =
        [NSURLComponents componentsWithURL:request.URL
                   resolvingAgainstBaseURL:YES];

    NSString *originalHost = components.host;
    NSNumber *originalPort = components.port;

    components.host = TARGET_IP;

    if (TARGET_PORT > 0) {
        components.port = @(TARGET_PORT);
    }

    req.URL = components.URL;

    if (originalHost) {
        NSString *hostHeader = originalHost;

        if (originalPort &&
            originalPort.integerValue != 80 &&
            originalPort.integerValue != 443) {

            hostHeader =
                [NSString stringWithFormat:@"%@:%@",
                                           originalHost,
                                           originalPort];
        }

        [req setValue:hostHeader forHTTPHeaderField:@"Host"];
    }

    return req;
}

- (void)startLoading {
    NSMutableURLRequest *req = [self.request mutableCopy];

    [NSURLProtocol setProperty:@YES
                        forKey:kIPRedirectProtocolHandledKey
                     inRequest:req];

    NSURLSessionConfiguration *cfg =
        [NSURLSessionConfiguration defaultSessionConfiguration];

    // Не запускаем IPRedirectProtocol повторно внутри нашей сессии.
    NSMutableArray *classes = [cfg.protocolClasses mutableCopy];

    [classes removeObject:[IPRedirectProtocol class]];

    cfg.protocolClasses = classes;

    NSURLSession *session =
        [NSURLSession sessionWithConfiguration:cfg
                                      delegate:self
                                 delegateQueue:nil];

    if (ENABLE_LOGGING) {
        NSLog(@"[IPRedirector] HTTP redirect -> %@",
              req.URL.absoluteString);
    }

    _dataTask = [session dataTaskWithRequest:req];

    [_dataTask resume];
}

- (void)stopLoading {
    [_dataTask cancel];
    _dataTask = nil;
}

- (void)URLSession:(NSURLSession *)session
          dataTask:(NSURLSessionDataTask *)dataTask
didReceiveResponse:(NSURLResponse *)response
 completionHandler:
    (void (^)(NSURLSessionResponseDisposition disposition))
        completionHandler {

    [self.client URLProtocol:self
          didReceiveResponse:response
          cacheStoragePolicy:NSURLCacheStorageNotAllowed];

    completionHandler(NSURLSessionResponseAllow);
}

- (void)URLSession:(NSURLSession *)session
          dataTask:(NSURLSessionDataTask *)dataTask
    didReceiveData:(NSData *)data {

    [self.client URLProtocol:self didLoadData:data];
}

- (void)URLSession:(NSURLSession *)session
              task:(NSURLSessionTask *)task
didCompleteWithError:(NSError *)error {

    if (error) {
        [self.client URLProtocol:self didFailWithError:error];
    } else {
        [self.client URLProtocolDidFinishLoading:self];
    }
}

@end


static NSURLSessionConfiguration *
(*orig_defaultSessionConfiguration)(id self, SEL _cmd);

static NSURLSessionConfiguration *
(*orig_ephemeralSessionConfiguration)(id self, SEL _cmd);


static NSURLSessionConfiguration *
swizzled_defaultSessionConfiguration(id self, SEL _cmd) {

    NSURLSessionConfiguration *cfg =
        orig_defaultSessionConfiguration(self, _cmd);

    NSMutableArray *classes = [cfg.protocolClasses mutableCopy];

    if (!classes) {
        classes = [NSMutableArray array];
    }

    if (![classes containsObject:[IPRedirectProtocol class]]) {
        [classes insertObject:[IPRedirectProtocol class] atIndex:0];
    }

    cfg.protocolClasses = classes;

    return cfg;
}


static NSURLSessionConfiguration *
swizzled_ephemeralSessionConfiguration(id self, SEL _cmd) {

    NSURLSessionConfiguration *cfg =
        orig_ephemeralSessionConfiguration(self, _cmd);

    NSMutableArray *classes = [cfg.protocolClasses mutableCopy];

    if (!classes) {
        classes = [NSMutableArray array];
    }

    if (![classes containsObject:[IPRedirectProtocol class]]) {
        [classes insertObject:[IPRedirectProtocol class] atIndex:0];
    }

    cfg.protocolClasses = classes;

    return cfg;
}


@implementation IPRedirector

+ (void)setupRedirector {

    [NSURLProtocol registerClass:[IPRedirectProtocol class]];

    Class cls = [NSURLSessionConfiguration class];

    Method defaultMethod =
        class_getClassMethod(
            cls,
            @selector(defaultSessionConfiguration)
        );

    if (defaultMethod) {

        orig_defaultSessionConfiguration =
            (NSURLSessionConfiguration *(*)(id, SEL))
            method_getImplementation(defaultMethod);

        method_setImplementation(
            defaultMethod,
            (IMP)swizzled_defaultSessionConfiguration
        );
    }


    Method ephemeralMethod =
        class_getClassMethod(
            cls,
            @selector(ephemeralSessionConfiguration)
        );

    if (ephemeralMethod) {

        orig_ephemeralSessionConfiguration =
            (NSURLSessionConfiguration *(*)(id, SEL))
            method_getImplementation(ephemeralMethod);

        method_setImplementation(
            ephemeralMethod,
            (IMP)swizzled_ephemeralSessionConfiguration
        );
    }


    if (ENABLE_LOGGING) {

        NSLog(
            @"[IPRedirector] initialized. HTTP target=%@:%d",
            TARGET_IP,
            TARGET_PORT
        );
    }
}

@end


__attribute__((constructor))
static void initIPRedirector(void) {

    @autoreleasepool {

        [IPRedirector setupRedirector];

    }
}
