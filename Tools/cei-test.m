//
// cei-test.m — exercises CEICard against a real card through CryptoTokenKit.
//   cei-test                          read-only checks (token info, certificates, PIN tries)
//   cei-test --export-auth-cert FILE  write the authentication certificate (DER) to FILE, nothing else
// Safe by construction: reads, PIN status, and (only with CEI_PIN set) one VERIFY of the user PIN,
// an authentication-key signature over a fixed hash, and personal-data presence (no values printed).
//
// SPDX-License-Identifier: AGPL-3.0-only
//
#import <CryptoTokenKit/CryptoTokenKit.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>
#import "../Shared/CEICard/CEICard+TKSmartCard.h"

static TKSmartCard *FirstCard(void) {
  TKSmartCardSlotManager *mgr = TKSmartCardSlotManager.defaultManager;
  if (!mgr) { printf("no slot manager (entitlement?)\n"); return nil; }
  for (NSString *name in mgr.slotNames) {
    dispatch_semaphore_t s = dispatch_semaphore_create(0);
    __block TKSmartCardSlot *slot = nil;
    [mgr getSlotWithName:name reply:^(TKSmartCardSlot *sl) { slot = sl; dispatch_semaphore_signal(s); }];
    dispatch_semaphore_wait(s, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));
    if (slot.state == TKSmartCardSlotStateValidCard) {
      fprintf(stderr, "reader: %s\n", name.UTF8String);
      return [slot makeSmartCard];
    }
  }
  printf("no card\n");
  return nil;
}

static void Status(CEICard *c, CEIPIN p) {
  CEIPINStatus st; NSError *e = nil;
  if ([c getStatusOfPIN:p status:&st error:&e])
    printf("  %-14s tries=%ld verified=%d blocked=%d\n", [CEICard displayNameForPIN:p].UTF8String,
           (long)st.triesLeft, st.verified, st.blocked);
  else printf("  %s status error: %s\n", [CEICard displayNameForPIN:p].UTF8String, e.localizedDescription.UTF8String);
}

static const char *Has(id v) { return v ? "present" : "-"; }

int main(int argc, const char **argv) {
  @autoreleasepool {
    NSString *pin = NSProcessInfo.processInfo.environment[@"CEI_PIN"];
    NSString *exportPath = (argc == 3 && strcmp(argv[1], "--export-auth-cert") == 0) ? @(argv[2]) : nil;
    TKSmartCard *sc = FirstCard();
    if (!sc) return 1;
    NSError *err = nil;
    if (exportPath) {
      __block NSData *der = nil;
      BOOL ok = [sc inSessionWithError:&err executeBlock:^BOOL(NSError **e) {
        der = [[[CEICard alloc] initWithTransport:sc] readCertificateForKey:CEIKeyAuthentication error:e];
        return der != nil;
      }];
      if (!ok || ![der writeToFile:exportPath atomically:YES]) {
        fprintf(stderr, "export failed: %s\n", err.localizedDescription.UTF8String ?: "write error");
        return 1;
      }
      return 0;
    }
    BOOL ok = [sc inSessionWithError:&err executeBlock:^BOOL(NSError **e) {
      CEICard *c = [[CEICard alloc] initWithTransport:sc];
      CEITokenInfo *ti = [c readTokenInfo:e];
      if (!ti) return NO;
      printf("token: label=%s manufacturer=%s serial=%s\n", ti.label.UTF8String, ti.manufacturer.UTF8String,
             ti.shortSerial.UTF8String);
      for (NSNumber *k in @[ @(CEIKeyAuthentication), @(CEIKeySigning) ]) {
        NSData *der = [c readCertificateForKey:k.integerValue error:e];
        if (!der) return NO;
        SecCertificateRef cert = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)der);
        CFStringRef subj = cert ? SecCertificateCopySubjectSummary(cert) : NULL;
        printf("cert %02lX: %lu bytes, parses=%s\n", (long)k.integerValue, (unsigned long)der.length,
               cert ? "yes" : "NO");
        if (subj) CFRelease(subj);
        if (cert) CFRelease(cert);
      }
      printf("PIN status:\n");
      Status(c, CEIPINUser); Status(c, CEIPINUserPUK); Status(c, CEIPINSignature); Status(c, CEIPINSignaturePUK);
      if (!pin) { printf("(no CEI_PIN: skipping VERIFY/sign/personal data)\n"); return YES; }

      CEIPINStatus st;
      if (![c getStatusOfPIN:CEIPINUser status:&st error:e]) return NO;
      if (!st.verified && st.triesLeft < 3) { printf("refusing: fewer than 3 tries left\n"); return YES; }
      if (![c verifyPIN:CEIPINUser value:pin error:e]) return NO;
      printf("VERIFY user PIN: ok\n");

      // Sign SHA-384 and SHA-256 digests, verify with the certificate's public key.
      NSData *der = [c readCertificateForKey:CEIKeyAuthentication error:e];
      SecCertificateRef cert = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)der);
      SecKeyRef pub = SecCertificateCopyKey(cert);
      const char *msg = "rocei native driver test";
      struct { const char *name; SecKeyAlgorithm alg; int len; } cases[] = {
        {"SHA-384", kSecKeyAlgorithmECDSASignatureDigestX962SHA384, CC_SHA384_DIGEST_LENGTH},
        {"SHA-256", kSecKeyAlgorithmECDSASignatureDigestX962SHA256, CC_SHA256_DIGEST_LENGTH},
        {"SHA-512", kSecKeyAlgorithmECDSASignatureDigestX962SHA512, CC_SHA512_DIGEST_LENGTH},
      };
      for (int i = 0; i < 3; i++) {
        uint8_t h[64];
        if (cases[i].len == 48) CC_SHA384(msg, (CC_LONG)strlen(msg), h);
        else if (cases[i].len == 32) CC_SHA256(msg, (CC_LONG)strlen(msg), h);
        else CC_SHA512(msg, (CC_LONG)strlen(msg), h);
        NSData *digest = [NSData dataWithBytes:h length:cases[i].len];
        NSData *raw = [c signDigest:digest withKey:CEIKeyAuthentication error:e];
        if (!raw) return NO;
        NSData *sig = CEIRawECDSAToDER(raw);
        CFErrorRef ve = NULL;
        BOOL good = SecKeyVerifySignature(pub, cases[i].alg, (__bridge CFDataRef)digest, (__bridge CFDataRef)sig, &ve);
        printf("sign %s with auth key: %s\n", cases[i].name, good ? "signature VERIFIED" : "verification FAILED");
        if (ve) CFRelease(ve);
      }
      CFRelease(pub); CFRelease(cert);

      CEIPersonalData *p = [c readPersonalData:e];
      if (!p) return NO;
      printf("personal data: last=%s first=%s gender=%s dob=%s cnp=%s(len %lu) citizenship=%s pob=%s doc=%s issued=%s "
             "expires=%s authority=%s address=%s temp=%lu foreign=%lu\n",
             Has(p.lastName), Has(p.firstName), Has(p.gender), Has(p.dateOfBirth), Has(p.personalNumber),
             (unsigned long)p.personalNumber.length, Has(p.citizenship), Has(p.placeOfBirth), Has(p.documentNumber),
             Has(p.issueDate), Has(p.expiryDate), Has(p.issuingAuthority), Has(p.permanentAddress),
             (unsigned long)p.temporaryResidences.count, (unsigned long)p.foreignResidences.count);
      return YES;
    }];
    if (!ok) { printf("FAILED: %s\n", err.localizedDescription.UTF8String); return 1; }
    return 0;
  }
}
