//
// CEICard.m
// RO CEI Connector
//
// SPDX-License-Identifier: AGPL-3.0-only
//

#import "CEICard.h"

NSErrorDomain const CEICardErrorDomain = @"ro.cei.card";
NSString *const CEICardTriesLeftKey = @"CEICardTriesLeft";
NSString *const CEICardStatusWordKey = @"CEICardStatusWord";

static const UInt16 SW_OK = 0x9000;
static const NSUInteger kPINBlockLength = 12;
static const NSUInteger kDigestLength = 48; // P-384

#pragma mark - Small helpers

static NSData *CEIHex(const char *hex) {
  NSMutableData *d = [NSMutableData data];
  for (const char *p = hex; p[0] && p[1]; p += 2) {
    char b[3] = {p[0], p[1], 0};
    uint8_t v = (uint8_t)strtoul(b, NULL, 16);
    [d appendBytes:&v length:1];
  }
  return d;
}

static NSError *CEIErr(CEICardError code, NSString *msg, NSDictionary *extra) {
  NSMutableDictionary *ui = [NSMutableDictionary dictionaryWithObject:msg forKey:NSLocalizedDescriptionKey];
  if (extra) [ui addEntriesFromDictionary:extra];
  return [NSError errorWithDomain:CEICardErrorDomain code:code userInfo:ui];
}

static NSError *CEISWErr(UInt16 sw, NSString *what) {
  return CEIErr(CEICardErrorUnexpectedStatus,
                [NSString stringWithFormat:NSLocalizedString(@"%@ failed (status %04X)", nil), what, sw],
                @{CEICardStatusWordKey : @(sw)});
}

#pragma mark - Minimal BER-TLV

typedef struct {
  NSUInteger tag;
  BOOL constructed;
  NSRange value; // range within the parent buffer
} CEITLV;

/// Parses consecutive TLVs in data[range]. Stops at 0x00/0xFF padding.
static NSArray<NSValue *> *CEIParseTLVs(NSData *data, NSRange range) {
  NSMutableArray *out = [NSMutableArray array];
  const uint8_t *b = data.bytes;
  NSUInteger i = range.location, end = NSMaxRange(range);
  while (i < end) {
    if (b[i] == 0x00 || b[i] == 0xFF) break;
    NSUInteger tag = b[i];
    BOOL constructed = (b[i] & 0x20) != 0;
    i++;
    if ((tag & 0x1F) == 0x1F) {
      do {
        if (i >= end) return out;
        tag = (tag << 8) | b[i];
      } while (b[i++] & 0x80);
    }
    if (i >= end) break;
    NSUInteger len = b[i++];
    if (len & 0x80) {
      NSUInteger n = len & 0x7F;
      if (n == 0 || n > 3 || i + n > end) break;
      len = 0;
      for (NSUInteger k = 0; k < n; k++) len = (len << 8) | b[i++];
    }
    if (i + len > end) break;
    CEITLV t = {tag, constructed, NSMakeRange(i, len)};
    [out addObject:[NSValue valueWithBytes:&t objCType:@encode(CEITLV)]];
    i += len;
  }
  return out;
}

static CEITLV CEITLVAt(NSArray<NSValue *> *list, NSUInteger idx) {
  CEITLV t;
  [list[idx] getValue:&t];
  return t;
}

/// First child TLV with the given tag, or NO.
static BOOL CEIFind(NSData *data, NSRange range, NSUInteger tag, CEITLV *out) {
  NSArray *list = CEIParseTLVs(data, range);
  for (NSUInteger i = 0; i < list.count; i++) {
    CEITLV t = CEITLVAt(list, i);
    if (t.tag == tag) {
      if (out) *out = t;
      return YES;
    }
  }
  return NO;
}

static NSString *_Nullable CEIString(NSData *data, NSRange r) {
  if (r.length == 0) return nil;
  NSString *s = [[NSString alloc] initWithData:[data subdataWithRange:r] encoding:NSUTF8StringEncoding];
  s = [s stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
  return s.length ? s : nil;
}

/// Dates on the card are 8 ASCII digits, DDMMYYYY.
static NSDateComponents *_Nullable CEIDate(NSData *data, NSRange r) {
  NSString *s = CEIString(data, r);
  if (s.length != 8) return nil;
  for (NSUInteger i = 0; i < 8; i++)
    if (!isdigit([s characterAtIndex:i])) return nil;
  NSDateComponents *c = [[NSDateComponents alloc] init];
  c.day = [s substringWithRange:NSMakeRange(0, 2)].integerValue;
  c.month = [s substringWithRange:NSMakeRange(2, 2)].integerValue;
  c.year = [s substringWithRange:NSMakeRange(4, 4)].integerValue;
  if (c.day < 1 || c.day > 31 || c.month < 1 || c.month > 12) return nil;
  return c;
}

#pragma mark - Public utilities

NSData *CEINormalizeDigest(NSData *digest, NSUInteger size) {
  if (digest.length == size) return digest;
  if (digest.length > size) return [digest subdataWithRange:NSMakeRange(0, size)];
  NSMutableData *d = [NSMutableData dataWithLength:size - digest.length];
  [d appendData:digest];
  return d;
}

static NSData *CEIDERInteger(const uint8_t *p, NSUInteger n) {
  while (n > 1 && p[0] == 0) { p++; n--; }
  NSMutableData *d = [NSMutableData data];
  uint8_t tag = 0x02;
  [d appendBytes:&tag length:1];
  BOOL pad = (p[0] & 0x80) != 0;
  uint8_t len = (uint8_t)(n + (pad ? 1 : 0));
  [d appendBytes:&len length:1];
  if (pad) {
    uint8_t z = 0;
    [d appendBytes:&z length:1];
  }
  [d appendBytes:p length:n];
  return d;
}

NSData *_Nullable CEIRawECDSAToDER(NSData *raw) {
  if (raw.length == 0 || raw.length % 2 != 0 || raw.length > 132) return nil;
  NSUInteger half = raw.length / 2;
  const uint8_t *b = raw.bytes;
  NSMutableData *body = [NSMutableData data];
  [body appendData:CEIDERInteger(b, half)];
  [body appendData:CEIDERInteger(b + half, half)];
  NSMutableData *out = [NSMutableData data];
  uint8_t seq = 0x30;
  [out appendBytes:&seq length:1];
  if (body.length < 0x80) {
    uint8_t l = (uint8_t)body.length;
    [out appendBytes:&l length:1];
  } else {
    uint8_t l[2] = {0x81, (uint8_t)body.length};
    [out appendBytes:l length:2];
  }
  [out appendData:body];
  return out;
}

NSData *_Nullable CEIPINBlock(NSString *pin, NSRange allowed) {
  if (pin.length < allowed.location || pin.length > NSMaxRange(allowed) - 1 ||
      pin.length > kPINBlockLength)
    return nil;
  NSMutableData *d = [NSMutableData dataWithCapacity:kPINBlockLength];
  for (NSUInteger i = 0; i < pin.length; i++) {
    unichar c = [pin characterAtIndex:i];
    if (c < '0' || c > '9') return nil;
    uint8_t v = (uint8_t)c;
    [d appendBytes:&v length:1];
  }
  while (d.length < kPINBlockLength) {
    uint8_t f = 0xFF;
    [d appendBytes:&f length:1];
  }
  return d;
}

#pragma mark - Model objects

@implementation CEITokenInfo
@end
@implementation CEIResidence
@end
@implementation CEIPersonalData
- (instancetype)init {
  if ((self = [super init])) {
    _temporaryResidences = @[];
    _foreignResidences = @[];
  }
  return self;
}
@end

#pragma mark - CEICard

@interface CEICard ()
@property(nonatomic, strong) id<CEITransport> transport;
@end

@implementation CEICard

+ (NSData *)idaAID { return CEIHex("A000000077030C60000000FE00000500"); }
+ (NSData *)genericAID { return CEIHex("E828BD080FD25047656E65726963"); }
+ (NSData *)eDataAID { return CEIHex("E828BD080FA0000001674544415441"); }

- (instancetype)initWithTransport:(id<CEITransport>)transport {
  if ((self = [super init])) {
    _transport = transport;
  }
  return self;
}

+ (CEIPIN)pinForKey:(CEIKey)key {
  return key == CEIKeySigning ? CEIPINSignature : CEIPINUser;
}

+ (NSRange)lengthRangeForPIN:(CEIPIN)pin {
  // The card would accept 4..12 / 6..12 digits, but Romanian eIDs are issued with (and the
  // official software only accepts) exactly 4 and 6 digits. Enforcing that here means a PIN of
  // the wrong length is rejected locally and never costs a try on the card.
  switch (pin) {
  case CEIPINUser: return NSMakeRange(4, 1);          // exactly 4
  case CEIPINSignature: return NSMakeRange(6, 1);     // exactly 6
  case CEIPINUserPUK:
  case CEIPINSignaturePUK: return NSMakeRange(8, 5);  // 8..12
  }
  return NSMakeRange(4, 1);
}

+ (NSString *)displayNameForPIN:(CEIPIN)pin {
  switch (pin) {
  case CEIPINUser: return NSLocalizedString(@"PIN", nil);
  case CEIPINUserPUK: return NSLocalizedString(@"PUK", nil);
  case CEIPINSignature: return NSLocalizedString(@"Signature PIN", nil);
  case CEIPINSignaturePUK: return NSLocalizedString(@"Signature PUK", nil);
  }
  return NSLocalizedString(@"PIN", nil);
}

#pragma mark APDU plumbing

/// Sends one command, transparently following 61xx with GET RESPONSE.
- (nullable NSData *)send:(UInt8)ins p1:(UInt8)p1 p2:(UInt8)p2 data:(nullable NSData *)data
                       le:(nullable NSNumber *)le sw:(UInt16 *)swOut error:(NSError **)error {
  UInt16 sw = 0;
  NSError *err = nil;
  NSData *resp = [self.transport sendIns:ins p1:p1 p2:p2 data:data le:le sw:&sw error:&err];
  if (!resp && err) {
    if (error) *error = CEIErr(CEICardErrorTransport, err.localizedDescription ?: NSLocalizedString(@"Card communication failed", nil),
                               @{NSUnderlyingErrorKey : err});
    return nil;
  }
  NSMutableData *all = [NSMutableData dataWithData:resp ?: [NSData data]];
  int guard = 0;
  while ((sw >> 8) == 0x61 && guard++ < 32) {
    NSUInteger n = sw & 0xFF;
    resp = [self.transport sendIns:0xC0 p1:0 p2:0 data:nil le:@(n == 0 ? 256 : n) sw:&sw error:&err];
    if (!resp && err) {
      if (error) *error = CEIErr(CEICardErrorTransport, err.localizedDescription ?: NSLocalizedString(@"Card communication failed", nil),
                                 @{NSUnderlyingErrorKey : err});
      return nil;
    }
    if (resp) [all appendData:resp];
  }
  *swOut = sw;
  return all;
}

- (BOOL)selectAID:(NSData *)aid name:(NSString *)name error:(NSError **)error {
  UInt16 sw = 0;
  if (![self send:0xA4 p1:0x04 p2:0x0C data:aid le:nil sw:&sw error:error]) return NO;
  if (sw != SW_OK) {
    if (error) *error = sw == 0x6A82 ? CEIErr(CEICardErrorNotThisCard, NSLocalizedString(@"Not a Romanian eID card", nil), nil)
                                     : CEISWErr(sw, [NSString stringWithFormat:@"SELECT %@", name]);
    return NO;
  }
  return YES;
}

/// Generic and EDATA are children of IDA and are only selectable from inside it. Selecting IDA
/// itself resets the security state (verified PINs), so try the target directly first and go
/// through IDA only when the card isn't inside it already (fresh reset or another app moved it).
- (BOOL)selectApplication:(NSData *)aid name:(NSString *)name error:(NSError **)error {
  UInt16 sw = 0;
  if (![self send:0xA4 p1:0x04 p2:0x0C data:aid le:nil sw:&sw error:error]) return NO;
  if (sw == SW_OK) return YES;
  if (![self selectAID:CEICard.idaAID name:@"IDA" error:error]) return NO;
  return [self selectAID:aid name:name error:error];
}

/// SELECT EF by FID and READ BINARY until the end of the file.
- (nullable NSData *)readFile:(UInt16)fid error:(NSError **)error {
  UInt16 sw = 0;
  uint8_t f[2] = {(uint8_t)(fid >> 8), (uint8_t)fid};
  if (![self send:0xA4 p1:0x02 p2:0x0C data:[NSData dataWithBytes:f length:2] le:nil sw:&sw error:error])
    return nil;
  if (sw != SW_OK) {
    if (error) *error = CEISWErr(sw, [NSString stringWithFormat:@"SELECT file %04X", fid]);
    return nil;
  }
  NSMutableData *out = [NSMutableData data];
  NSUInteger expected = NSUIntegerMax;
  while (out.length < 0x8000) {
    NSUInteger off = out.length;
    NSUInteger want = 0xE0;
    if (expected != NSUIntegerMax) {
      if (off >= expected) break;
      want = MIN(want, expected - off);
    }
    NSData *chunk = [self send:0xB0 p1:(UInt8)(off >> 8) p2:(UInt8)off data:nil le:@(want) sw:&sw error:error];
    if (!chunk) return nil;
    if (sw == 0x6982) {
      if (error) *error = CEIErr(CEICardErrorPINRequired, NSLocalizedString(@"PIN required", nil), nil);
      return nil;
    }
    if (sw == 0x6B00 || (sw == 0x6282 && chunk.length == 0)) break; // past end of file
    if (sw != SW_OK && sw != 0x6282) {
      if (error) *error = CEISWErr(sw, [NSString stringWithFormat:@"READ BINARY %04X", fid]);
      return nil;
    }
    [out appendData:chunk];
    if (off == 0 && expected == NSUIntegerMax) {
      // If the file is one DER object, learn its total size to avoid reading past the end.
      const uint8_t *b = out.bytes;
      if (out.length >= 2 && (b[0] == 0x30 || (b[0] & 0xE0) == 0xA0)) {
        NSUInteger hl = 2, l = b[1];
        if (l & 0x80) {
          NSUInteger n = l & 0x7F;
          if (n >= 1 && n <= 3 && out.length >= 2 + n) {
            l = 0;
            for (NSUInteger k = 0; k < n; k++) l = (l << 8) | b[2 + k];
            hl = 2 + n;
          } else {
            l = NSUIntegerMax - hl;
          }
        }
        if (l != NSUIntegerMax - hl) expected = hl + l;
      }
    }
    if (chunk.length < want || sw == 0x6282) break;
  }
  if (expected != NSUIntegerMax && out.length > expected) [out setLength:expected];
  return out;
}

#pragma mark Token info / certificates

- (nullable CEITokenInfo *)readTokenInfo:(NSError **)error {
  if (![self selectApplication:CEICard.genericAID name:@"PKI" error:error]) return nil;
  NSData *d = [self readFile:0x5032 error:error];
  if (!d) return nil;
  CEITLV seq;
  if (!CEIFind(d, NSMakeRange(0, d.length), 0x30, &seq)) {
    if (error) *error = CEIErr(CEICardErrorParse, NSLocalizedString(@"Malformed TokenInfo", nil), nil);
    return nil;
  }
  CEITokenInfo *ti = [[CEITokenInfo alloc] init];
  NSArray *items = CEIParseTLVs(d, seq.value);
  for (NSUInteger i = 0; i < items.count; i++) {
    CEITLV t = CEITLVAt(items, i);
    if (t.tag == 0x04 && !ti.serialNumber) ti.serialNumber = [d subdataWithRange:t.value];
    else if (t.tag == 0x0C && !ti.manufacturer) ti.manufacturer = CEIString(d, t.value);
    else if (t.tag == 0x80 && !ti.label) ti.label = CEIString(d, t.value);
  }
  if (!ti.serialNumber.length) {
    if (error) *error = CEIErr(CEICardErrorParse, NSLocalizedString(@"TokenInfo has no serial number", nil), nil);
    return nil;
  }
  NSMutableString *hex = [NSMutableString string];
  const uint8_t *b = ti.serialNumber.bytes;
  for (NSUInteger i = 0; i < ti.serialNumber.length; i++) [hex appendFormat:@"%02X", b[i]];
  ti.serialHex = hex;
  ti.shortSerial = hex.length > 16 ? [hex substringFromIndex:hex.length - 16] : hex;
  if (!ti.manufacturer) ti.manufacturer = @"";
  if (!ti.label) ti.label = @"";
  return ti;
}

- (nullable NSData *)readCertificateForKey:(CEIKey)key error:(NSError **)error {
  if (![self selectApplication:CEICard.genericAID name:@"PKI" error:error]) return nil;
  UInt16 fid = key == CEIKeySigning ? 0xCE8E : 0xCE81;
  NSData *d = [self readFile:fid error:error];
  if (!d) return nil;
  if (d.length < 4 || ((const uint8_t *)d.bytes)[0] != 0x30) {
    if (error) *error = CEIErr(CEICardErrorParse, NSLocalizedString(@"Certificate file is not DER", nil), nil);
    return nil;
  }
  return d;
}

#pragma mark PIN

- (BOOL)getStatusOfPIN:(CEIPIN)pin status:(CEIPINStatus *)status error:(NSError **)error {
  if (![self selectApplication:CEICard.genericAID name:@"PKI" error:error]) return NO;
  UInt16 sw = 0;
  if (![self send:0x20 p1:0x00 p2:pin data:nil le:nil sw:&sw error:error]) return NO;
  CEIPINStatus s = {-1, NO, NO};
  if (sw == SW_OK) s.verified = YES;
  else if ((sw & 0xFFF0) == 0x63C0) s.triesLeft = sw & 0x0F;
  else if (sw == 0x6983) { s.blocked = YES; s.triesLeft = 0; }
  if (s.triesLeft == 0) s.blocked = YES;
  if (status) *status = s;
  return YES;
}

- (NSError *)pinErrorForStatus:(UInt16)sw what:(NSString *)what {
  if ((sw & 0xFFF0) == 0x63C0) {
    NSInteger left = sw & 0x0F;
    if (left == 0) return CEIErr(CEICardErrorPINBlocked, NSLocalizedString(@"PIN is blocked", nil), @{CEICardTriesLeftKey : @0});
    return CEIErr(CEICardErrorWrongPIN,
                  [NSString localizedStringWithFormat:NSLocalizedString(@"Wrong PIN (%ld tries left)", nil), (long)left],
                  @{CEICardTriesLeftKey : @(left)});
  }
  if (sw == 0x6983) return CEIErr(CEICardErrorPINBlocked, NSLocalizedString(@"PIN is blocked", nil), @{CEICardTriesLeftKey : @0});
  return CEISWErr(sw, what);
}

- (BOOL)verifyPIN:(CEIPIN)pin value:(NSString *)value error:(NSError **)error {
  NSData *block = CEIPINBlock(value, [CEICard lengthRangeForPIN:pin]);
  if (!block) {
    if (error) *error = CEIErr(CEICardErrorInvalidPINFormat, NSLocalizedString(@"PIN has the wrong length or contains non-digits", nil), nil);
    return NO;
  }
  if (![self selectApplication:CEICard.genericAID name:@"PKI" error:error]) return NO;
  UInt16 sw = 0;
  NSData *r = [self send:0x20 p1:0x00 p2:pin data:block le:nil sw:&sw error:error];
  if (!r) return NO;
  if (sw == SW_OK) return YES;
  if (error) *error = [self pinErrorForStatus:sw what:@"VERIFY"];
  return NO;
}

- (BOOL)changePIN:(CEIPIN)pin from:(NSString *)oldValue to:(NSString *)newValue error:(NSError **)error {
  NSRange range = [CEICard lengthRangeForPIN:pin];
  NSData *o = CEIPINBlock(oldValue, range), *n = CEIPINBlock(newValue, range);
  if (!o || !n) {
    if (error) *error = CEIErr(CEICardErrorInvalidPINFormat, NSLocalizedString(@"PIN has the wrong length or contains non-digits", nil), nil);
    return NO;
  }
  if (![self selectApplication:CEICard.genericAID name:@"PKI" error:error]) return NO;
  NSMutableData *data = [NSMutableData dataWithData:o];
  [data appendData:n];
  UInt16 sw = 0;
  if (![self send:0x24 p1:0x00 p2:pin data:data le:nil sw:&sw error:error]) return NO;
  if (sw == SW_OK) return YES;
  if (error) *error = [self pinErrorForStatus:sw what:@"CHANGE PIN"];
  return NO;
}

#pragma mark Signing

- (nullable NSData *)signDigest:(NSData *)digest withKey:(CEIKey)key error:(NSError **)error {
  if (digest.length == 0) {
    if (error) *error = CEIErr(CEICardErrorParse, NSLocalizedString(@"Empty digest", nil), nil);
    return nil;
  }
  NSData *hash = CEINormalizeDigest(digest, kDigestLength);
  if (![self selectApplication:CEICard.genericAID name:@"PKI" error:error]) return nil;

  // The authentication key only allows INTERNAL AUTHENTICATE (PSO CDS returns 6982), verified on a card.
  // The signing key is tried with PSO COMPUTE DIGITAL SIGNATURE first, then INTERNAL AUTHENTICATE.
  NSArray<NSNumber *> *methods = key == CEIKeySigning ? @[ @0xB6, @0xA4 ] : @[ @0xA4 ];
  UInt16 sw = 0;
  NSError *lastError = nil;
  for (NSNumber *crt in methods) {
    uint8_t mse[] = {0x80, 0x01, 0x04, 0x84, 0x01, (uint8_t)key};
    if (![self send:0x22 p1:0x41 p2:crt.unsignedCharValue data:[NSData dataWithBytes:mse length:sizeof mse]
                 le:nil sw:&sw error:error])
      return nil;
    if (sw != SW_OK) {
      lastError = CEISWErr(sw, @"MSE SET");
      continue;
    }
    NSData *sig = crt.unsignedCharValue == 0xB6
                      ? [self send:0x2A p1:0x9E p2:0x9A data:hash le:@0 sw:&sw error:error]
                      : [self send:0x88 p1:0x00 p2:0x00 data:hash le:@0 sw:&sw error:error];
    if (!sig) return nil;
    if (sw == SW_OK && sig.length == 2 * kDigestLength) return sig;
    if (sw == 0x6982) {
      lastError = CEIErr(CEICardErrorPINRequired, NSLocalizedString(@"PIN required", nil), nil);
      continue;
    }
    lastError = sw == SW_OK ? CEIErr(CEICardErrorParse, NSLocalizedString(@"Unexpected signature length", nil), nil)
                            : CEISWErr(sw, NSLocalizedString(@"Signature", nil));
  }
  if (error) *error = lastError;
  return nil;
}

#pragma mark Personal data

static NSArray<CEIResidence *> *CEIParseResidences(NSData *d) {
  NSMutableArray *out = [NSMutableArray array];
  CEITLV seq, list;
  if (!CEIFind(d, NSMakeRange(0, d.length), 0x30, &seq)) return out;
  if (!CEIFind(d, seq.value, 0xA0, &list)) return out;
  NSArray *recs = CEIParseTLVs(d, list.value);
  for (NSUInteger i = 0; i < recs.count; i++) {
    CEITLV rec = CEITLVAt(recs, i);
    if (rec.tag != 0x30) continue;
    CEIResidence *r = [[CEIResidence alloc] init];
    CEITLV f;
    if (CEIFind(d, rec.value, 0x80, &f)) r.address = CEIString(d, f.value);
    if (CEIFind(d, rec.value, 0x81, &f)) r.startDate = CEIDate(d, f.value);
    if (CEIFind(d, rec.value, 0x82, &f)) r.endDate = CEIDate(d, f.value);
    if (r.address || r.startDate || r.endDate) [out addObject:r];
  }
  return out;
}

- (nullable CEIPersonalData *)readPersonalData:(NSError **)error {
  if (![self selectApplication:CEICard.eDataAID name:@"EDATA" error:error]) return nil;
  CEIPersonalData *p = [[CEIPersonalData alloc] init];
  CEITLV seq, f;

  NSData *dg1 = [self readFile:0x0101 error:error];
  if (!dg1) return nil;
  if (CEIFind(dg1, NSMakeRange(0, dg1.length), 0x30, &seq)) {
    if (CEIFind(dg1, seq.value, 0x80, &f)) p.lastName = CEIString(dg1, f.value);
    if (CEIFind(dg1, seq.value, 0x81, &f)) p.firstName = CEIString(dg1, f.value);
    if (CEIFind(dg1, seq.value, 0x82, &f)) p.gender = CEIString(dg1, f.value);
    if (CEIFind(dg1, seq.value, 0x83, &f)) p.dateOfBirth = CEIDate(dg1, f.value);
    if (CEIFind(dg1, seq.value, 0x84, &f)) p.personalNumber = CEIString(dg1, f.value);
    if (CEIFind(dg1, seq.value, 0x85, &f)) p.citizenship = CEIString(dg1, f.value);
  }

  // The remaining groups are optional: a read failure leaves the fields empty.
  NSData *dg2 = [self readFile:0x0102 error:NULL];
  if (dg2 && CEIFind(dg2, NSMakeRange(0, dg2.length), 0x30, &seq)) {
    if (!p.dateOfBirth && CEIFind(dg2, seq.value, 0x80, &f)) p.dateOfBirth = CEIDate(dg2, f.value);
    if (CEIFind(dg2, seq.value, 0x81, &f)) p.placeOfBirth = CEIString(dg2, f.value);
  }
  NSData *dg4 = [self readFile:0x0104 error:NULL];
  if (dg4 && CEIFind(dg4, NSMakeRange(0, dg4.length), 0x30, &seq)) {
    if (CEIFind(dg4, seq.value, 0x80, &f)) p.documentNumber = CEIString(dg4, f.value);
    if (CEIFind(dg4, seq.value, 0x81, &f)) p.issueDate = CEIDate(dg4, f.value);
    if (CEIFind(dg4, seq.value, 0x82, &f)) p.expiryDate = CEIDate(dg4, f.value);
    if (CEIFind(dg4, seq.value, 0x83, &f)) p.issuingAuthority = CEIString(dg4, f.value);
  }
  NSData *dg6 = [self readFile:0x0106 error:NULL];
  if (dg6 && CEIFind(dg6, NSMakeRange(0, dg6.length), 0x30, &seq) && CEIFind(dg6, seq.value, 0x80, &f))
    p.permanentAddress = CEIString(dg6, f.value);
  NSData *dg7 = [self readFile:0x0107 error:NULL];
  if (dg7) p.temporaryResidences = CEIParseResidences(dg7);
  NSData *dg8 = [self readFile:0x0108 error:NULL];
  if (dg8) p.foreignResidences = CEIParseResidences(dg8);
  return p;
}

@end
