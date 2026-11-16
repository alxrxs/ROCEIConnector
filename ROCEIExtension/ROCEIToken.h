//
// ROCEIToken.h
// RO CEI Connector
//
// CryptoTokenKit smart card token for the Romanian eID. Created by the system when a card
// with the IDA application is inserted. All card access goes through CEICard (native APDUs).
//
// SPDX-License-Identifier: AGPL-3.0-only
//

#import <CryptoTokenKit/CryptoTokenKit.h>
#import "../Shared/CEICard/CEICard.h"

NS_ASSUME_NONNULL_BEGIN

/// Keychain object IDs (also used as the key handle in the session).
extern NSString *const ROCEIObjectAuthKey;
extern NSString *const ROCEIObjectAuthCert;
extern NSString *const ROCEIObjectSignKey;
extern NSString *const ROCEIObjectSignCert;

@interface ROCEITokenDriver : TKSmartCardTokenDriver <TKSmartCardTokenDriverDelegate>
@end

@interface ROCEIToken : TKSmartCardToken <TKTokenDelegate>
- (nullable instancetype)initWithSmartCard:(TKSmartCard *)smartCard
                                       AID:(nullable NSData *)AID
                               tokenDriver:(ROCEITokenDriver *)tokenDriver
                                     error:(NSError **)error;
@end

@interface ROCEITokenSession : TKSmartCardTokenSession <TKTokenSessionDelegate>
@end

NS_ASSUME_NONNULL_END
