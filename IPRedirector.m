#import "IPRedirector.h"
#import "Config.h"
#import "../vendor/fishhook.h"
#import <objc/runtime.h>
#import <Security/Security.h>

static NSString *const kIPRedirectProtocolHandledKey = @"kIPRedirectProtocolHandledKey";

static bool (*orig_SecTrustEvaluateWithError)(SecTrustRef trust, CFErrorRef *error);
static OSStatus (*orig_SecTrustEvaluate)(SecTrustRef trust, SecTrustResultType *result);

static bool my_SecTrustEvaluateWithError(SecTrustRef trust, CFErrorRef *error) {
    if (BYPASS_SSL_CERTIFICATES) {
        if (error) *error = NULL;
        return true;
    }
    return orig_SecTrustEvaluateWithError(trust, error);
}

static OSStatus my_SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result) {
    if (BYPASS_SSL_CERTIFICATES) {
        if (result) *result = kSecTrustResultProceed;
        return errSecSuccess;
    }
    return orig_SecTrustEvaluate(trust, result);
}

@implementation IPRedirectProtocol {
    NSURLSessionDataTask *_dataTask;
}

+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    if ([NSURLProtocol propertyForKey:kIPRedirectProtocolHandledKey inRequest:request]) {
        return NO;
    }
    
    NSString *scheme = [[request.URL scheme] lowercaseString];
    if (![scheme isEqualToString:@"http"] && ![scheme isEqualToString:@"https"]) {
        return NO;
    }
    
    NSString *host = request.URL.host;
    if (!host || [host isEqualToString:TARGET_IP]) {
        return NO;
    }
    
    if (REDIRECT_ALL_HTTP) {
        return YES;
    }
    
    NSArray *hosts = TARGET_HOSTS_TO_REPLACE;
    for (NSString *targetHost in hosts) {
        if ([host isEqualToString:targetHost]) {
            return YES;
        }
    }
    
    return NO;
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request {
    NSMutableURLRequest *mutableReq = [request mutableCopy];
    
    NSURLComponents *components = [NSURLComponents componentsWithURL:request.URL resolvingAgainstBaseURL:YES];
    NSString *originalHost = components.host;
    NSNumber *originalPort = components.port;
    
    components.host = TARGET_IP;
    if (TARGET_PORT > 0) {
        components.port = @(TARGET_PORT);
    }
    
    mutableReq.URL = components.URL;
    
    if (originalHost) {
        NSString *hostHeader = originalHost;
        if (originalPort && [originalPort integerValue] != 80 && [originalPort integerValue] != 443) {
            hostHeader = [NSString stringWithFormat:@"%@:%@", originalHost, originalPort];
        }
        [mutableReq setValue:hostHeader forHTTPHeaderField:@"Host"];
    }
    
    return mutableReq;
}

- (void)startLoading {
    NSMutableURLRequest *mutableRequest = [self.request mutableCopy];
    [NSURLProtocol setProperty:@YES forKey:kIPRedirectProtocolHandledKey inRequest:mutableRequest];
    
    NSURLSessionConfiguration *config = [NSURLSessionConfiguration defaultSessionConfiguration];
    NSURLSession *session = [NSURLSession sessionWithConfiguration:config delegate:self delegateQueue:nil];
    
    if (ENABLE_LOGGING) {
        NSLog(@"[IPRedirector] Redirecting request to: %@", mutableRequest.URL.absoluteString);
    }
    
    _dataTask = [session dataTaskWithRequest:mutableRequest];
    [_dataTask resume];
}

- (void)stopLoading {
    [_dataTask cancel];
    _dataTask = nil;
}

- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask didReceiveResponse:(NSURLResponse *)response completionHandler:(void (^)(NSURLSessionResponseDisposition disposition))completionHandler {
    [self.client URLProtocol:self didReceiveResponse:response cacheStoragePolicy:NSURLCacheStorageNotAllowed];
    completionHandler(NSURLSessionResponseAllow);
}

- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask didReceiveData:(NSData *)data {
    [self.client URLProtocol:self didLoadData:data];
}

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error {
    if (error) {
        [self.client URLProtocol:self didFailWithError:error];
    } else {
        [self.client URLProtocolDidFinishLoading:self];
    }
}

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential * _Nullable credential))completionHandler {
    if (BYPASS_SSL_CERTIFICATES && [challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        completionHandler(NSURLSessionAuthChallengeUseCredential, [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust]);
    } else {
        completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
    }
}

@end

static NSURLSessionConfiguration *(*orig_defaultSessionConfiguration)(id self, SEL _cmd);
static NSURLSessionConfiguration *(*orig_ephemeralSessionConfiguration)(id self, SEL _cmd);

static NSURLSessionConfiguration *swizzled_defaultSessionConfiguration(id self, SEL _cmd) {
    NSURLSessionConfiguration *config = orig_defaultSessionConfiguration(self, _cmd);
    NSMutableArray *protocols = [config.protocolClasses mutableCopy];
    if (![protocols containsObject:[IPRedirectProtocol class]]) {
        [protocols insertObject:[IPRedirectProtocol class] atIndex:0];
    }
    config.protocolClasses = protocols;
    return config;
}

static NSURLSessionConfiguration *swizzled_ephemeralSessionConfiguration(id self, SEL _cmd) {
    NSURLSessionConfiguration *config = orig_ephemeralSessionConfiguration(self, _cmd);
    NSMutableArray *protocols = [config.protocolClasses mutableCopy];
    if (![protocols containsObject:[IPRedirectProtocol class]]) {
        [protocols insertObject:[IPRedirectProtocol class] atIndex:0];
    }
    config.protocolClasses = protocols;
    return config;
}

@implementation IPRedirector

+ (void)setupRedirector {
    [NSURLProtocol registerClass:[IPRedirectProtocol class]];
    
    Class sessionConfigClass = [NSURLSessionConfiguration class];
    
    Method origDefaultMethod = class_getClassMethod(sessionConfigClass, @selector(defaultSessionConfiguration));
    if (origDefaultMethod) {
        orig_defaultSessionConfiguration = (NSURLSessionConfiguration *(*)(id, SEL))method_getImplementation(origDefaultMethod);
        method_setImplementation(origDefaultMethod, (IMP)swizzled_defaultSessionConfiguration);
    }
    
    Method origEphemeralMethod = class_getClassMethod(sessionConfigClass, @selector(ephemeralSessionConfiguration));
    if (origEphemeralMethod) {
        orig_ephemeralSessionConfiguration = (NSURLSessionConfiguration *(*)(id, SEL))method_getImplementation(origEphemeralMethod);
        method_setImplementation(origEphemeralMethod, (IMP)swizzled_ephemeralSessionConfiguration);
    }
    
    if (BYPASS_SSL_CERTIFICATES) {
        rebind_symbols((struct rebinding[]){
            {"SecTrustEvaluateWithError", (void *)my_SecTrustEvaluateWithError, (void **)&orig_SecTrustEvaluateWithError},
            {"SecTrustEvaluate", (void *)my_SecTrustEvaluate, (void **)&orig_SecTrustEvaluate}
        }, 2);
    }
    
    if (ENABLE_LOGGING) {
        NSLog(@"[IPRedirector] Successfully initialized. Target IP: %@", TARGET_IP);
    }
}

@end

__attribute__((constructor)) static void initIPRedirector(void) {
    @autoreleasepool {
        [IPRedirector setupRedirector];
    }
}
