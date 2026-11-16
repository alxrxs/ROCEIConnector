//
// CEICard.h
// RO CEI Connector
//
// Native (APDU-level) driver for the Romanian electronic identity card
// (Cartea Electronică de Identitate, IDEMIA "ID-A" on Cosmo X), contact interface.
// Written from protocol observation of the card itself, without IDEMIA code.
//
// SPDX-License-Identifier: AGPL-3.0-only
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

extern NSErrorDomain const CEICardErrorDomain;

typedef NS_ERROR_ENUM(CEICardErrorDomain, CEICardError) {
  CEICardErrorTransport = 1,      ///< reader/transport failure
  CEICardErrorUnexpectedStatus,   ///< card returned an unexpected status word
  CEICardErrorNotThisCard,        ///< card is not a Romanian eID
  CEICardErrorWrongPIN,           ///< PIN rejected; userInfo[CEICardTriesLeftKey]
  CEICardErrorPINBlocked,         ///< PIN blocked (0 tries left)
  CEICardErrorPINRequired,        ///< security status not satisfied
  CEICardErrorInvalidPINFormat,   ///< PIN length/charset outside card policy (nothing sent)
  CEICardErrorParse,              ///< malformed data on card
};

/// NSNumber with remaining tries, set on CEICardErrorWrongPIN.
extern NSString *const CEICardTriesLeftKey;
/// NSNumber with the status word, set on CEICardErrorUnexpectedStatus.
extern NSString *const CEICardStatusWordKey;

/// Minimal APDU transport. TKSmartCard conforms (see CEICard+TKSmartCard.h).
/// Must be called inside an exclusive card session.
@protocol CEITransport <NSObject>
- (nullable NSData *)sendIns:(UInt8)ins
                          p1:(UInt8)p1
                          p2:(UInt8)p2
                        data:(nullable NSData *)requestData
                          le:(nullable NSNumber *)le
                          sw:(UInt16 *)sw
                       error:(NSError **)error;
@end

typedef NS_ENUM(NSInteger, CEIKey) {
  CEIKeyAuthentication = 0x81, ///< P-384, protected by the 4-digit user PIN (ref 03)
  CEIKeySigning = 0x8E,        ///< P-384, protected by the 6-digit "advanced signature" PIN (ref 05)
};

typedef NS_ENUM(UInt8, CEIPIN) {
  CEIPINUser = 0x03,          ///< "User PIN" (short), exactly 4 digits
  CEIPINUserPUK = 0x04,       ///< "PUC" for the user PIN, min 8
  CEIPINSignature = 0x05,     ///< "ADVANCED SIGNATURE PIN" (long), exactly 6 digits
  CEIPINSignaturePUK = 0x0A,  ///< "ADVANCED SIGNATURE PUC", min 8
};

/// PIN status from an empty VERIFY (never consumes a try).
typedef struct {
  NSInteger triesLeft;  ///< -1 when unknown
  BOOL verified;        ///< already verified in the current card session
  BOOL blocked;
} CEIPINStatus;

@interface CEITokenInfo : NSObject
@property(nonatomic, copy) NSData *serialNumber;     ///< raw 16 bytes from TokenInfo
@property(nonatomic, copy) NSString *serialHex;      ///< uppercase hex of the full serial
@property(nonatomic, copy) NSString *shortSerial;    ///< last 8 bytes as hex (what IDplugManager shows)
@property(nonatomic, copy) NSString *manufacturer;   ///< e.g. "DGEP"
@property(nonatomic, copy) NSString *label;          ///< e.g. "PKI Application"
@end

@interface CEIResidence : NSObject
@property(nonatomic, copy, nullable) NSString *address;
@property(nonatomic, copy, nullable) NSDateComponents *startDate;
@property(nonatomic, copy, nullable) NSDateComponents *endDate;
@end

/// Card holder data from the EDATA application (requires the user PIN).
@interface CEIPersonalData : NSObject
@property(nonatomic, copy, nullable) NSString *lastName;
@property(nonatomic, copy, nullable) NSString *firstName;
@property(nonatomic, copy, nullable) NSString *gender;
@property(nonatomic, copy, nullable) NSDateComponents *dateOfBirth;
@property(nonatomic, copy, nullable) NSString *personalNumber;   ///< CNP
@property(nonatomic, copy, nullable) NSString *citizenship;
@property(nonatomic, copy, nullable) NSString *placeOfBirth;
@property(nonatomic, copy, nullable) NSString *documentNumber;   ///< series + number
@property(nonatomic, copy, nullable) NSDateComponents *issueDate;
@property(nonatomic, copy, nullable) NSDateComponents *expiryDate;
@property(nonatomic, copy, nullable) NSString *issuingAuthority;
@property(nonatomic, copy, nullable) NSString *permanentAddress;
@property(nonatomic, copy) NSArray<CEIResidence *> *temporaryResidences;
@property(nonatomic, copy) NSArray<CEIResidence *> *foreignResidences;
@end

@interface CEICard : NSObject

/// AIDs (public for Info.plist matching and tests).
@property(class, nonatomic, readonly) NSData *idaAID;
@property(class, nonatomic, readonly) NSData *genericAID;
@property(class, nonatomic, readonly) NSData *eDataAID;

- (instancetype)initWithTransport:(id<CEITransport>)transport NS_DESIGNATED_INITIALIZER;
- (instancetype)init NS_UNAVAILABLE;

/// SELECT IDA → Generic and read TokenInfo. Fails with CEICardErrorNotThisCard for other cards.
- (nullable CEITokenInfo *)readTokenInfo:(NSError **)error;

/// DER X.509 certificate for a key (public data, no PIN).
- (nullable NSData *)readCertificateForKey:(CEIKey)key error:(NSError **)error;

/// Remaining tries via empty VERIFY (no try consumed). Returns NO only on transport errors.
- (BOOL)getStatusOfPIN:(CEIPIN)pin status:(CEIPINStatus *)status error:(NSError **)error;

/// VERIFY with a user-supplied PIN. Validates format first; sends exactly one VERIFY.
- (BOOL)verifyPIN:(CEIPIN)pin value:(NSString *)value error:(NSError **)error;

/// CHANGE REFERENCE DATA (old → new). Validates both values first; sends exactly one command.
- (BOOL)changePIN:(CEIPIN)pin from:(NSString *)oldValue to:(NSString *)newValue error:(NSError **)error;

/// ECDSA over a pre-computed digest. The key's PIN must be verified in this card session first.
/// Digest is normalized to 48 bytes (left-padded / truncated per ECDSA). Returns raw r||s (96 bytes).
- (nullable NSData *)signDigest:(NSData *)digest withKey:(CEIKey)key error:(NSError **)error;

/// Personal data (EDATA). The user PIN must have been verified in this card session.
- (nullable CEIPersonalData *)readPersonalData:(NSError **)error;

/// PIN reference that protects a key.
+ (CEIPIN)pinForKey:(CEIKey)key;
/// Allowed PIN length (location = minimum, NSMaxRange - 1 = maximum), digits only.
+ (NSRange)lengthRangeForPIN:(CEIPIN)pin;
+ (NSString *)displayNameForPIN:(CEIPIN)pin;

@end

/// Utilities exposed for tests.
NSData *_Nullable CEIRawECDSAToDER(NSData *raw);
NSData *CEINormalizeDigest(NSData *digest, NSUInteger size);
NSData *_Nullable CEIPINBlock(NSString *pin, NSRange allowedLength);

NS_ASSUME_NONNULL_END
