//
// ROCEIToken.m
// RO CEI Connector
//
// SPDX-License-Identifier: AGPL-3.0-only
//

#import "ROCEIToken.h"
#import "../Shared/CEICard/CEICard+TKSmartCard.h"
#import <os/log.h>

NSString *const ROCEIObjectAuthKey = @"auth-key";
NSString *const ROCEIObjectAuthCert = @"auth-cert";
NSString *const ROCEIObjectSignKey = @"sign-key";
NSString *const ROCEIObjectSignCert = @"sign-cert";

static os_log_t ROCEILog(void) {
  static os_log_t log;
  static dispatch_once_t once;
  dispatch_once(&once, ^{ log = os_log_create("com.alxrxs.rocei.connector", "token"); });
  return log;
}

#pragma mark - Driver

@implementation ROCEITokenDriver

- (instancetype)init {
  if ((self = [super init])) {
    self.delegate = self;
  }
  return self;
}

- (nullable TKSmartCardToken *)tokenDriver:(TKSmartCardTokenDriver *)driver
                   createTokenForSmartCard:(TKSmartCard *)smartCard
                                       AID:(nullable NSData *)AID
                                     error:(NSError **)error {
  os_log(ROCEILog(), "card inserted in %{public}@", smartCard.slot.name);
  return [[ROCEIToken alloc] initWithSmartCard:smartCard AID:AID tokenDriver:self error:error];
}

@end

#pragma mark - Token

@implementation ROCEIToken

- (nullable instancetype)initWithSmartCard:(TKSmartCard *)smartCard
                                       AID:(nullable NSData *)AID
                               tokenDriver:(ROCEITokenDriver *)tokenDriver
                                     error:(NSError **)error {
  __block CEITokenInfo *info = nil;
  __block NSData *authCert = nil, *signCert = nil;
  NSError *cardError = nil;
  BOOL ok = [smartCard inSessionWithError:&cardError
                             executeBlock:^BOOL(NSError **e) {
                               CEICard *card = [[CEICard alloc] initWithTransport:smartCard];
                               info = [card readTokenInfo:e];
                               if (!info) return NO;
                               authCert = [card readCertificateForKey:CEIKeyAuthentication error:e];
                               if (!authCert) return NO;
                               // The signing certificate is optional: a card without it still works for login.
                               signCert = [card readCertificateForKey:CEIKeySigning error:NULL];
                               return YES;
                             }];
  if (!ok) {
    os_log_error(ROCEILog(), "not usable as RO eID: %{public}@", cardError);
    if (error) {
      *error = [NSError errorWithDomain:TKErrorDomain
                                   code:TKErrorCodeCorruptedData
                               userInfo:@{
                                 NSLocalizedDescriptionKey : cardError.localizedDescription ?: NSLocalizedString(@"Card read failed", nil),
                                 NSUnderlyingErrorKey : cardError ?: [NSNull null]
                               }];
    }
    return nil;
  }

  NSString *instanceID = [@"rocei-" stringByAppendingString:info.serialHex];
  if (!(self = [super initWithSmartCard:smartCard AID:AID instanceID:instanceID tokenDriver:tokenDriver])) {
    return nil;
  }
  self.delegate = self;

  NSMutableArray<TKTokenKeychainItem *> *items = [NSMutableArray array];
  if (![self addItemsForCertificate:authCert
                             certID:ROCEIObjectAuthCert
                              keyID:ROCEIObjectAuthKey
                              label:NSLocalizedString(@"RO eID Authentication", nil)
                                key:CEIKeyAuthentication
                           forLogin:YES
                               into:items]) {
    if (error) {
      *error = [NSError errorWithDomain:TKErrorDomain
                                   code:TKErrorCodeCorruptedData
                               userInfo:@{NSLocalizedDescriptionKey : NSLocalizedString(@"Authentication certificate is corrupted", nil)}];
    }
    return nil;
  }
  if (signCert) {
    [self addItemsForCertificate:signCert
                          certID:ROCEIObjectSignCert
                           keyID:ROCEIObjectSignKey
                           label:NSLocalizedString(@"RO eID Signature", nil)
                             key:CEIKeySigning
                        forLogin:NO
                            into:items];
  }
  [self.keychainContents fillWithItems:items];
  os_log(ROCEILog(), "token %{public}@ ready with %lu items", instanceID, (unsigned long)items.count);
  return self;
}

- (BOOL)addItemsForCertificate:(NSData *)der
                        certID:(NSString *)certID
                         keyID:(NSString *)keyID
                         label:(NSString *)label
                           key:(CEIKey)key
                      forLogin:(BOOL)forLogin
                          into:(NSMutableArray<TKTokenKeychainItem *> *)items {
  SecCertificateRef cert = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)der);
  if (!cert) return NO;

  TKTokenKeychainCertificate *certItem = [[TKTokenKeychainCertificate alloc] initWithCertificate:cert objectID:certID];
  certItem.label = label;

  TKTokenKeychainKey *keyItem = [[TKTokenKeychainKey alloc] initWithCertificate:cert objectID:keyID];
  CFRelease(cert);
  if (!keyItem) return NO;
  keyItem.label = label;
  keyItem.canSign = YES;
  keyItem.canDecrypt = NO;
  keyItem.canPerformKeyExchange = NO;
  keyItem.suitableForLogin = forLogin;
  // One constraint per PIN reference: authenticating for one key never unlocks the other.
  NSString *constraint = [NSString stringWithFormat:@"PIN%02X", [CEICard pinForKey:key]];
  keyItem.constraints = @{@(TKTokenOperationSignData) : constraint};

  [items addObject:certItem];
  [items addObject:keyItem];
  return YES;
}

- (nullable TKTokenSession *)token:(TKToken *)token createSessionWithError:(NSError **)error {
  return [[ROCEITokenSession alloc] initWithToken:self];
}

@end
