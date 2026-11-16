//
// CEICard+TKSmartCard.h
// RO CEI Connector
//
// SPDX-License-Identifier: AGPL-3.0-only
//

#import <CryptoTokenKit/CryptoTokenKit.h>
#import "CEICard.h"

/// TKSmartCard already implements -sendIns:p1:p2:data:le:sw:error:; declare conformance.
@interface TKSmartCard (CEITransport) <CEITransport>
@end
