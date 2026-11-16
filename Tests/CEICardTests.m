//
// CEICardTests.m — card-free tests for CEICard (fake transport replaying the card's real
// public structures; personal data uses synthetic values).
//
// SPDX-License-Identifier: AGPL-3.0-only
//
#import <Foundation/Foundation.h>
#import "../Shared/CEICard/CEICard.h"

static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { failures++; printf("FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); } else printf("ok   %s\n", msg); } while (0)

static NSData *Hex(NSString *h) {
  NSMutableData *d = [NSMutableData data];
  for (NSUInteger i = 0; i + 1 < h.length; i += 2) {
    uint8_t b = (uint8_t)strtoul([[h substringWithRange:NSMakeRange(i, 2)] UTF8String], NULL, 16);
    [d appendBytes:&b length:1];
  }
  return d;
}

/// Minimal card model: applications, files, PIN refs. Mirrors the observed selection rules.
@interface FakeCard : NSObject <CEITransport>
@property(nonatomic, copy) NSString *currentApp;    // nil = MF
@property(nonatomic, copy) NSDictionary<NSString *, NSDictionary<NSNumber *, NSData *> *> *files;
@property(nonatomic, strong) NSData *currentFile;
@property(nonatomic) NSInteger tries;
@property(nonatomic) BOOL verified;
@property(nonatomic) NSUInteger verifyCount;
@property(nonatomic, strong) NSMutableArray<NSString *> *log;
@end

@implementation FakeCard
- (instancetype)init {
  if ((self = [super init])) { _tries = 5; _log = [NSMutableArray array]; }
  return self;
}
- (NSData *)sendIns:(UInt8)ins p1:(UInt8)p1 p2:(UInt8)p2 data:(NSData *)d le:(NSNumber *)le sw:(UInt16 *)sw error:(NSError **)error {
  [self.log addObject:[NSString stringWithFormat:@"%02X", ins]];
  NSString *ida = @"A000000077030C60000000FE00000500";
  NSString *gen = @"E828BD080FD25047656E65726963", *edata = @"E828BD080FA0000001674544415441";
  if (ins == 0xA4 && p1 == 0x04) {
    NSMutableString *aid = [NSMutableString string];
    const uint8_t *b = d.bytes;
    for (NSUInteger i = 0; i < d.length; i++) [aid appendFormat:@"%02X", b[i]];
    if ([aid isEqual:ida]) { self.currentApp = @"IDA"; self.verified = NO; *sw = 0x9000; return [NSData data]; }
    BOOL insideIDA = [self.currentApp isEqual:@"IDA"] || [self.currentApp isEqual:@"GEN"] || [self.currentApp isEqual:@"EDATA"];
    if (insideIDA && ([aid isEqual:gen] || [aid isEqual:edata])) {
      self.currentApp = [aid isEqual:gen] ? @"GEN" : @"EDATA"; *sw = 0x9000; return [NSData data];
    }
    *sw = 0x6A82; return [NSData data];
  }
  if (ins == 0xA4 && p1 == 0x02) {
    UInt16 fid = (UInt16)((((const uint8_t *)d.bytes)[0] << 8) | ((const uint8_t *)d.bytes)[1]);
    self.currentFile = self.files[self.currentApp ?: @""][@(fid)];
    *sw = self.currentFile ? 0x9000 : 0x6A82; return [NSData data];
  }
  if (ins == 0xB0) {
    if ([self.currentApp isEqual:@"EDATA"] && !self.verified) { *sw = 0x6982; return [NSData data]; }
    NSUInteger off = ((NSUInteger)p1 << 8) | p2, n = le.unsignedIntegerValue ?: 256;
    if (off >= self.currentFile.length) { *sw = 0x6B00; return [NSData data]; }
    *sw = 0x9000; return [self.currentFile subdataWithRange:NSMakeRange(off, MIN(n, self.currentFile.length - off))];
  }
  if (ins == 0x20) {
    if (d.length == 0) { *sw = self.verified ? 0x9000 : (UInt16)(0x63C0 | self.tries); return [NSData data]; }
    self.verifyCount++;
    NSData *good = Hex(@"31323334FFFFFFFFFFFFFFFF");
    if ([d isEqual:good]) { self.verified = YES; self.tries = 5; *sw = 0x9000; }
    else { self.tries--; *sw = (UInt16)(0x63C0 | self.tries); }
    return [NSData data];
  }
  if (ins == 0x22) { *sw = 0x9000; return [NSData data]; }
  if (ins == 0x88 || ins == 0x2A) {
    if (!self.verified || ins == 0x2A) { *sw = 0x6982; return [NSData data]; }
    *sw = 0x9000; return [NSMutableData dataWithLength:96];
  }
  *sw = 0x6D00; return [NSData data];
}
@end

static NSData *TLV(uint8_t tag, NSData *v) {
  NSMutableData *d = [NSMutableData dataWithBytes:&tag length:1];
  uint8_t l = (uint8_t)v.length;
  [d appendBytes:&l length:1];
  [d appendData:v];
  return d;
}
static NSData *U(NSString *s) { return [s dataUsingEncoding:NSUTF8StringEncoding]; }

int main(void) {
  @autoreleasepool {
    // --- pure helpers
    CHECK(CEINormalizeDigest([NSMutableData dataWithLength:32], 48).length == 48, "short digest is left-padded to 48");
    NSMutableData *d64 = [NSMutableData dataWithLength:64];
    ((uint8_t *)d64.mutableBytes)[0] = 0xAB;
    NSData *n = CEINormalizeDigest(d64, 48);
    CHECK(n.length == 48 && ((const uint8_t *)n.bytes)[0] == 0xAB, "long digest keeps leftmost 48 bytes");

    NSMutableData *raw = [NSMutableData dataWithLength:96];
    ((uint8_t *)raw.mutableBytes)[0] = 0x80;  // r needs a 0x00 pad
    ((uint8_t *)raw.mutableBytes)[95] = 0x01; // s is small
    NSData *der = CEIRawECDSAToDER(raw);
    const uint8_t *b = der.bytes;
    CHECK(b[0] == 0x30 && b[2] == 0x02 && b[3] == 49 && b[4] == 0x00, "DER pads r with 0x00 when high bit set");
    CHECK(der.length == 2 + 2 + 49 + 2 + 1, "DER strips leading zeros of s");
    CHECK(CEIRawECDSAToDER([NSData dataWithBytes:"x" length:1]) == nil, "odd-length raw signature rejected");

    NSRange user = [CEICard lengthRangeForPIN:CEIPINUser], sign = [CEICard lengthRangeForPIN:CEIPINSignature];
    CHECK([CEIPINBlock(@"1234", user) isEqual:Hex(@"31323334FFFFFFFFFFFFFFFF")], "PIN block is ASCII padded with FF to 12");
    CHECK(CEIPINBlock(@"123", user) == nil, "3-digit PIN rejected locally");
    CHECK(CEIPINBlock(@"12345", user) == nil, "5-digit PIN rejected locally (Romanian PIN is exactly 4)");
    CHECK(CEIPINBlock(@"12a4", user) == nil, "non-digit PIN rejected locally");
    CHECK(CEIPINBlock(@"123456", sign) != nil, "6-digit signature PIN accepted");
    CHECK(CEIPINBlock(@"12345", sign) == nil && CEIPINBlock(@"1234567", sign) == nil, "signature PIN must be exactly 6");
    CHECK(CEIPINBlock(@"1234567890123", NSMakeRange(4, 9)) == nil, "PIN longer than 12 never fits the block");

    // --- card flows on the fake
    NSData *tokenInfo = Hex(@"302C020101041000112233445566770123456789ABCDEF0C044447455080"
                            @"0F504B49204170706C69636174696F6E");
    NSMutableData *cert = [NSMutableData dataWithData:Hex(@"308203F4")];
    [cert appendData:[NSMutableData dataWithLength:0x3F4]];
    NSMutableData *dg1body = [NSMutableData data];
    [dg1body appendData:TLV(0x80, U(@"POPESCU"))];
    [dg1body appendData:TLV(0x81, U(@"ION-ANDREI"))];
    [dg1body appendData:TLV(0x82, U(@"M"))];
    [dg1body appendData:TLV(0x83, U(@"01021990"))];
    [dg1body appendData:TLV(0x84, U(@"1900201000000"))];
    [dg1body appendData:TLV(0x85, U(@"ROU"))];
    NSMutableData *res = [NSMutableData data];
    [res appendData:TLV(0x80, U(@"Str. Exemplu 1, Cluj-Napoca"))];
    [res appendData:TLV(0x81, U(@"01012020"))];
    NSData *dg7 = TLV(0x30, TLV(0xA0, TLV(0x30, res)));
    FakeCard *fake = [[FakeCard alloc] init];
    fake.files = @{
      @"GEN" : @{@0x5032 : tokenInfo, @0xCE81 : cert, @0xCE8E : cert},
      @"EDATA" : @{@0x0101 : TLV(0x30, dg1body), @0x0106 : TLV(0x30, TLV(0x80, U(@"Jud. Cluj, Mun. Cluj-Napoca"))),
                   @0x0107 : dg7},
    };
    CEICard *card = [[CEICard alloc] initWithTransport:fake];
    NSError *e = nil;

    CEITokenInfo *ti = [card readTokenInfo:&e];
    CHECK([ti.shortSerial isEqual:@"0123456789ABCDEF"], "TokenInfo serial (as IDplugManager shows it)");
    CHECK([ti.label isEqual:@"PKI Application"] && [ti.manufacturer isEqual:@"DGEP"], "TokenInfo label/manufacturer");

    NSData *c = [card readCertificateForKey:CEIKeyAuthentication error:&e];
    CHECK(c.length == 0x3F8, "certificate read across multiple READ BINARY chunks, trimmed to DER length");

    CEIPINStatus st;
    CHECK([card getStatusOfPIN:CEIPINUser status:&st error:&e] && st.triesLeft == 5 && !st.verified, "PIN status without using a try");

    CHECK([card signDigest:[NSMutableData dataWithLength:32] withKey:CEIKeyAuthentication error:&e] == nil &&
              e.code == CEICardErrorPINRequired, "signing without PIN reports PIN required");

    e = nil;
    CHECK(![card verifyPIN:CEIPINUser value:@"12" error:&e] && e.code == CEICardErrorInvalidPINFormat &&
              fake.verifyCount == 0, "malformed PIN never reaches the card");

    CHECK(![card verifyPIN:CEIPINUser value:@"9999" error:&e] && e.code == CEICardErrorWrongPIN &&
              [e.userInfo[CEICardTriesLeftKey] integerValue] == 4 && fake.verifyCount == 1,
          "wrong PIN: exactly one VERIFY, tries reported");

    CHECK([card verifyPIN:CEIPINUser value:@"1234" error:&e], "correct PIN verifies");
    NSData *sig = [card signDigest:[NSMutableData dataWithLength:48] withKey:CEIKeyAuthentication error:&e];
    CHECK(sig.length == 96, "signature after VERIFY (state kept: no IDA reselect)");

    CEIPersonalData *p = [card readPersonalData:&e];
    CHECK([p.lastName isEqual:@"POPESCU"] && [p.firstName isEqual:@"ION-ANDREI"], "DG1 names");
    CHECK(p.dateOfBirth.day == 1 && p.dateOfBirth.month == 2 && p.dateOfBirth.year == 1990, "DG1 date is DDMMYYYY");
    CHECK([p.personalNumber isEqual:@"1900201000000"] && [p.citizenship isEqual:@"ROU"], "DG1 CNP, citizenship");
    CHECK([p.permanentAddress hasPrefix:@"Jud. Cluj"], "DG6 domicile");
    CHECK(p.temporaryResidences.count == 1 && p.temporaryResidences[0].startDate.year == 2020, "DG7 residence record");
    CHECK(fake.verified, "reading EDATA from inside IDA keeps the verified state");

    printf("%s (%d failure%s)\n", failures ? "FAILED" : "PASSED", failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
  }
}
