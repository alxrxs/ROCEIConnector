//
// ROCEITokenSession.m
// RO CEI Connector
//
// Signing and PIN handling for the Romanian eID token.
//
// The system hands us the card through -getSmartCardWithError: with an exclusive session already
// open and the IDA application selected (com.apple.ctk.aid). Selecting IDA resets the card's
// security state, so every signing request has to present the PIN again.
//
// PIN safety rules:
//  - A PIN is only sent because the user typed it into the system PIN dialog.
//  - A newly entered PIN is "pending": it is sent exactly once (VERIFY). If the card rejects it, it
//    is discarded immediately and the user is asked again. It is never retried automatically.
//  - Once the card has accepted a PIN, it is kept for this session (in memory only) and re-presented
//    before each signature. Re-presenting a PIN the card accepted cannot consume a try. If the card
//    ever rejects it (e.g. the PIN was changed elsewhere), it is discarded at once.
//
// SPDX-License-Identifier: AGPL-3.0-only
//

#import "ROCEIToken.h"
#import "../Shared/CEICard/CEICard+TKSmartCard.h"
#import <CommonCrypto/CommonDigest.h>
#import <os/log.h>

static os_log_t ROCEISessionLog(void) {
  static os_log_t log;
  static dispatch_once_t once;
  dispatch_once(&once, ^{ log = os_log_create("com.alxrxs.rocei.connector", "session"); });
  return log;
}

static NSError *ROCEITKError(TKErrorCode code, NSString *message) {
  return [NSError errorWithDomain:TKErrorDomain code:code userInfo:@{NSLocalizedDescriptionKey : message}];
}

/// Maps CEICard errors onto CryptoTokenKit errors the system understands.
static NSError *ROCEIMapError(NSError *e) {
  if (![e.domain isEqualToString:CEICardErrorDomain]) return e;
  TKErrorCode code;
  switch ((CEICardError)e.code) {
  case CEICardErrorWrongPIN:
  case CEICardErrorPINBlocked:
  case CEICardErrorInvalidPINFormat: code = TKErrorCodeAuthenticationFailed; break;
  case CEICardErrorPINRequired: code = TKErrorCodeAuthenticationNeeded; break;
  case CEICardErrorTransport: code = TKErrorCodeCommunicationError; break;
  default: code = TKErrorCodeCorruptedData; break;
  }
  return [NSError errorWithDomain:TKErrorDomain
                             code:code
                         userInfo:@{NSLocalizedDescriptionKey : e.localizedDescription, NSUnderlyingErrorKey : e}];
}

#pragma mark - Algorithms

typedef NS_ENUM(NSInteger, ROCEIHash) { ROCEIHashNone, ROCEIHashSHA1, ROCEIHashSHA224, ROCEIHashSHA256, ROCEIHashSHA384, ROCEIHashSHA512 };

typedef struct {
  BOOL supported;
  ROCEIHash hash;  ///< hash to apply to the input (None = input already is a digest)
  BOOL rawOutput;  ///< RFC 4754 r||s instead of X9.62 DER
} ROCEIAlgorithm;

static ROCEIAlgorithm ROCEIClassify(TKTokenKeyAlgorithm *a) {
  struct { SecKeyAlgorithm alg; ROCEIHash hash; BOOL raw; } table[] = {
      {kSecKeyAlgorithmECDSASignatureDigestX962, ROCEIHashNone, NO},
      {kSecKeyAlgorithmECDSASignatureDigestX962SHA1, ROCEIHashNone, NO},
      {kSecKeyAlgorithmECDSASignatureDigestX962SHA224, ROCEIHashNone, NO},
      {kSecKeyAlgorithmECDSASignatureDigestX962SHA256, ROCEIHashNone, NO},
      {kSecKeyAlgorithmECDSASignatureDigestX962SHA384, ROCEIHashNone, NO},
      {kSecKeyAlgorithmECDSASignatureDigestX962SHA512, ROCEIHashNone, NO},
      {kSecKeyAlgorithmECDSASignatureMessageX962SHA1, ROCEIHashSHA1, NO},
      {kSecKeyAlgorithmECDSASignatureMessageX962SHA224, ROCEIHashSHA224, NO},
      {kSecKeyAlgorithmECDSASignatureMessageX962SHA256, ROCEIHashSHA256, NO},
      {kSecKeyAlgorithmECDSASignatureMessageX962SHA384, ROCEIHashSHA384, NO},
      {kSecKeyAlgorithmECDSASignatureMessageX962SHA512, ROCEIHashSHA512, NO},
      {kSecKeyAlgorithmECDSASignatureDigestRFC4754, ROCEIHashNone, YES},
      {kSecKeyAlgorithmECDSASignatureDigestRFC4754SHA1, ROCEIHashNone, YES},
      {kSecKeyAlgorithmECDSASignatureDigestRFC4754SHA224, ROCEIHashNone, YES},
      {kSecKeyAlgorithmECDSASignatureDigestRFC4754SHA256, ROCEIHashNone, YES},
      {kSecKeyAlgorithmECDSASignatureDigestRFC4754SHA384, ROCEIHashNone, YES},
      {kSecKeyAlgorithmECDSASignatureDigestRFC4754SHA512, ROCEIHashNone, YES},
      {kSecKeyAlgorithmECDSASignatureMessageRFC4754SHA1, ROCEIHashSHA1, YES},
      {kSecKeyAlgorithmECDSASignatureMessageRFC4754SHA224, ROCEIHashSHA224, YES},
      {kSecKeyAlgorithmECDSASignatureMessageRFC4754SHA256, ROCEIHashSHA256, YES},
      {kSecKeyAlgorithmECDSASignatureMessageRFC4754SHA384, ROCEIHashSHA384, YES},
      {kSecKeyAlgorithmECDSASignatureMessageRFC4754SHA512, ROCEIHashSHA512, YES},
  };
  for (size_t i = 0; i < sizeof table / sizeof table[0]; i++) {
    if ([a isAlgorithm:table[i].alg]) return (ROCEIAlgorithm){YES, table[i].hash, table[i].raw};
  }
  return (ROCEIAlgorithm){NO, ROCEIHashNone, NO};
}

static NSData *ROCEIApplyHash(ROCEIHash h, NSData *m) {
  uint8_t out[CC_SHA512_DIGEST_LENGTH];
  CC_LONG n = (CC_LONG)m.length;
  switch (h) {
  case ROCEIHashNone: return m;
  case ROCEIHashSHA1: CC_SHA1(m.bytes, n, out); return [NSData dataWithBytes:out length:CC_SHA1_DIGEST_LENGTH];
  case ROCEIHashSHA224: CC_SHA224(m.bytes, n, out); return [NSData dataWithBytes:out length:CC_SHA224_DIGEST_LENGTH];
  case ROCEIHashSHA256: CC_SHA256(m.bytes, n, out); return [NSData dataWithBytes:out length:CC_SHA256_DIGEST_LENGTH];
  case ROCEIHashSHA384: CC_SHA384(m.bytes, n, out); return [NSData dataWithBytes:out length:CC_SHA384_DIGEST_LENGTH];
  case ROCEIHashSHA512: CC_SHA512(m.bytes, n, out); return [NSData dataWithBytes:out length:CC_SHA512_DIGEST_LENGTH];
  }
  return m;
}

#pragma mark - PIN store

@interface ROCEIPIN : NSObject
@property(nonatomic, copy) NSString *value;
@property(nonatomic) BOOL acceptedByCard;
@end
@implementation ROCEIPIN
@end

@interface ROCEITokenSession ()
@property(nonatomic, strong) NSMutableDictionary<NSNumber *, ROCEIPIN *> *pins; ///< PIN ref → value
- (BOOL)storeEnteredPIN:(NSString *)pin ref:(CEIPIN)ref error:(NSError **)error;
@end

#pragma mark - PIN operation

@interface ROCEIPINOperation : TKTokenPasswordAuthOperation
@property(nonatomic, weak) ROCEITokenSession *session;
@property(nonatomic) CEIPIN pinRef;
@end

@implementation ROCEIPINOperation

- (BOOL)finishWithError:(NSError **)error {
  ROCEITokenSession *session = self.session;
  NSString *pin = self.password;
  self.password = nil;
  if (!session || pin.length == 0) {
    if (error) *error = ROCEITKError(TKErrorCodeCanceledByUser, NSLocalizedString(@"No PIN entered", nil));
    return NO;
  }
  return [session storeEnteredPIN:pin ref:self.pinRef error:error];
}

@end

#pragma mark - Session

@implementation ROCEITokenSession

- (instancetype)initWithToken:(TKToken *)token {
  if ((self = [super initWithToken:token])) {
    self.delegate = self;
    _pins = [NSMutableDictionary dictionary];
  }
  return self;
}

- (BOOL)storeEnteredPIN:(NSString *)pin ref:(CEIPIN)ref error:(NSError **)error {
  NSRange allowed = [CEICard lengthRangeForPIN:ref];
  if (!CEIPINBlock(pin, allowed)) {
    // Rejected locally: nothing is sent to the card, no try is used.
    if (error) {
      NSString *msg = allowed.length == 1
          ? [NSString stringWithFormat:NSLocalizedString(@"%@ must be %lu digits", nil), [CEICard displayNameForPIN:ref],
                                       (unsigned long)allowed.location]
          : [NSString stringWithFormat:NSLocalizedString(@"%@ must be %lu–%lu digits", nil),
                                       [CEICard displayNameForPIN:ref], (unsigned long)allowed.location,
                                       (unsigned long)(NSMaxRange(allowed) - 1)];
      *error = ROCEITKError(TKErrorCodeAuthenticationFailed, msg);
    }
    return NO;
  }
  ROCEIPIN *p = [[ROCEIPIN alloc] init];
  p.value = pin;
  p.acceptedByCard = NO;
  self.pins[@(ref)] = p;
  os_log(ROCEISessionLog(), "PIN entered for ref %02X", ref);
  return YES;
}

#pragma mark TKTokenSessionDelegate

- (nullable TKTokenAuthOperation *)tokenSession:(TKTokenSession *)session
                         beginAuthForOperation:(TKTokenOperation)operation
                                    constraint:(TKTokenOperationConstraint)constraint
                                         error:(NSError **)error {
  CEIPIN ref;
  if ([constraint isEqual:@"PIN03"]) ref = CEIPINUser;
  else if ([constraint isEqual:@"PIN05"]) ref = CEIPINSignature;
  else {
    if (error) *error = ROCEITKError(TKErrorCodeBadParameter, NSLocalizedString(@"Unexpected constraint", nil));
    return nil;
  }
  os_log(ROCEISessionLog(), "PIN requested for ref %02X", ref);
  ROCEIPINOperation *op = [[ROCEIPINOperation alloc] init];
  op.session = self;
  op.pinRef = ref;
  return op;
}

- (BOOL)tokenSession:(TKTokenSession *)session
    supportsOperation:(TKTokenOperation)operation
             usingKey:(TKTokenObjectID)keyObjectID
            algorithm:(TKTokenKeyAlgorithm *)algorithm {
  if (operation != TKTokenOperationSignData) return NO;
  if (![keyObjectID isEqual:ROCEIObjectAuthKey] && ![keyObjectID isEqual:ROCEIObjectSignKey]) return NO;
  return ROCEIClassify(algorithm).supported;
}

- (nullable NSData *)tokenSession:(TKTokenSession *)session
                         signData:(NSData *)dataToSign
                         usingKey:(TKTokenObjectID)keyObjectID
                        algorithm:(TKTokenKeyAlgorithm *)algorithm
                            error:(NSError **)error {
  ROCEIAlgorithm alg = ROCEIClassify(algorithm);
  if (!alg.supported) {
    if (error) *error = ROCEITKError(TKErrorCodeNotImplemented, NSLocalizedString(@"Unsupported algorithm", nil));
    return nil;
  }
  CEIKey key = [keyObjectID isEqual:ROCEIObjectSignKey] ? CEIKeySigning : CEIKeyAuthentication;
  CEIPIN ref = [CEICard pinForKey:key];
  ROCEIPIN *pin = self.pins[@(ref)];
  if (!pin) {
    if (error) *error = ROCEITKError(TKErrorCodeAuthenticationNeeded, NSLocalizedString(@"PIN required", nil));
    return nil;
  }

  NSError *cardError = nil;
  TKSmartCard *sc = [self getSmartCardWithError:&cardError];
  if (!sc) {
    if (error) *error = cardError ?: ROCEITKError(TKErrorCodeCommunicationError, NSLocalizedString(@"Card not available", nil));
    return nil;
  }
  CEICard *card = [[CEICard alloc] initWithTransport:sc];

  // Exactly one VERIFY per request. A PIN the card rejects is discarded for good.
  if (![card verifyPIN:ref value:pin.value error:&cardError]) {
    [self.pins removeObjectForKey:@(ref)];
    os_log_error(ROCEISessionLog(), "VERIFY ref %02X rejected (was accepted before: %d): %{public}@", ref,
                 pin.acceptedByCard, cardError.localizedDescription);
    if (error) *error = ROCEIMapError(cardError);
    return nil;
  }
  pin.acceptedByCard = YES;

  NSData *raw = [card signDigest:ROCEIApplyHash(alg.hash, dataToSign) withKey:key error:&cardError];
  if (!raw) {
    os_log_error(ROCEISessionLog(), "sign with key %02lX failed: %{public}@", (long)key, cardError.localizedDescription);
    if (error) *error = ROCEIMapError(cardError);
    return nil;
  }
  os_log(ROCEISessionLog(), "signed with key %02lX", (long)key);
  if (alg.rawOutput) return raw;
  NSData *der = CEIRawECDSAToDER(raw);
  if (!der && error) *error = ROCEITKError(TKErrorCodeCorruptedData, NSLocalizedString(@"Bad signature from card", nil));
  return der;
}

@end
