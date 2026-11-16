# Native CryptoTokenKit driver for the Romanian eID (no IDEMIA code)

## Intent
IDEMIA's `libidplug-pkcs11` is unreliable: it keeps a cross-process SysV-semaphore lock, shows UI from a
separate process, and competes with CryptoTokenKit for the reader. The user has had to reboot the Mac to recover.
The current app also requires explicit "add card" registration (persistent token).
Goal: plug the card in and macOS sees the eID immediately, using a FOSS implementation of the card protocol.

## Goals
- Insert card → token appears (TKSmartCardTokenDriver matched by AID). Remove card → token disappears.
- Two identities: Authentication (key 0x81, PIN ref 03, 4-12 digits) and Signing (key 0x8E, PIN ref 05, 6-12 digits).
  Both are P-384 ECDSA and appear in Keychain Access / Safari / `sc_auth identities`.
- Companion app (optional for operation), modelled on IDplugManager:
  card info + PIN/PUK tries left, certificates, change PIN / unblock with PUK, personal data (needs short PIN).
- Zero IDEMIA code or binaries shipped or loaded.

## Non-goals
- Qualified (QSCD) signatures: Romanian cards are not issued with a qualified certificate.
- NFC/PACE/CAN. Contact readers don't need it.
- DG3 (parents), DG5 (photo), DG10+: locked even with the PIN (need terminal authentication).

## Anti-goals
- Anything that could lock or alter the card by accident. PIN commands are only sent with user-entered PINs,
  never retried automatically. Remaining tries are shown before each PIN entry in the app.

## Approaches considered
1. **Native APDUs inside the CTK extension (chosen).** CTK owns the reader session, so there's no PC/SC contention,
   no helper process and no dylib.
2. FOSS PKCS#11 module (Rust, forked from peru-dnie-pkcs11) loaded by the extension. Adds a process boundary and
   the same PC/SC contention as today. Deferred: can be built later on the same protocol notes.
3. OpenSC driver. Widest reach, but slow to upstream and it doesn't fix the macOS insertion UX by itself.

## Protocol (verified on a real card, contact reader)
See `~/re-idplug/notes/FINDINGS.md`. Summary:
- SELECT IDA `A000000077030C60000000FE00000500` first (Generic and EDATA are children of IDA; the current DF persists).
- Generic PKI ADF `E828BD080FD25047656E65726963`: PKCS#15. Certs CE81 (auth) and CE8E (sign); TokenInfo 5032.
- VERIFY `00 20 00 <ref> 0C <ASCII PIN padded with FF to 12>`. Empty VERIFY → `63Cx` gives tries left.
- Auth signature (verified): MSE `00 22 41 A4 06 80 01 04 84 01 81`, INTERNAL AUTHENTICATE `00 88 00 00 30 <hash48> 00`
  → raw r||s (96 bytes). Digests are left-padded with zeros (shorter) or truncated to the leftmost 48 bytes (longer),
  per the ECDSA definition.
- Signing key 0x8E: try PSO CDS (`00 22 41 B6 … 84 01 8E`, `00 2A 9E 9A`), fall back to INTERNAL AUTHENTICATE (to be confirmed with the user's 6-digit PIN).
- Personal data: EDATA `E828BD080FA0000001674544415441`, VERIFY 03, files 0101/0102/0104/0106/0107/0108/0109.
  TLV layouts are in FINDINGS.md; text is UTF-8, dates are DDMMYYYY.

## Structure
- `Shared/CEICard/`: transport-agnostic card library (ObjC). `CEICard` talks to an `id<CEITransport>`
  (TKSmartCard in the extension and app; a test transport in unit tests). Parses PKCS#15 bits, DGs and certs.
- `ROCEIExtension/`: `ROCEITokenDriver` (TKSmartCardTokenDriver), `ROCEIToken` (TKSmartCardToken),
  `ROCEITokenSession` (TKSmartCardTokenSession). The PIN comes from a `TKTokenPasswordAuthOperation` (system dialog);
  the session sends VERIFY itself (CTK's PIN-format API can't pad with 0xFF).
- `ROCEIConnector/`: SwiftUI companion app (Observation framework) using CEICard over `TKSmartCardSlotManager`.
- Removed: ROCEIHelper, LaunchAgent, PKCS11 wrapper, IDEMIA dylib copy/hash logic, persistent registration,
  the Xcode project (it referenced the removed targets).
- `build.sh`: runs the unit tests, then builds and signs without Xcode (only Command Line Tools are installed).
  Install swaps the bundle atomically so LaunchServices never unregisters the extension mid-install.

## Phase 2 (not blocking)
- ECDH for `sc_auth` pairing / login: the PKCS#15 usage says sign-only, but the old code reported HW DERIVE.
  Find the native command by static analysis, then test with the user's consent.
- Confirm the signing-key (0x8E) command with the user's 6-digit PIN.

## Learned during implementation (verified on the real card)
- Selecting IDA resets the card's security state; Generic/EDATA must be selected directly when already inside IDA.
  CEICard tries the target AID first and only goes through IDA on 6A82.
- The system selects IDA (com.apple.ctk.aid) before every token request, so each signature re-presents the PIN.
  A newly entered PIN is sent once; only PINs the card accepted are re-presented.
- `TKSmartCardTokenSession.smartCard` is deprecated (macOS 26): use `-getSmartCardWithError:`, which already
  holds an exclusive session (don't nest `inSession`).
- The plist needs `com.apple.ctk.token-type = smartcard` alongside `com.apple.ctk.aid`.
- Programmatic PIN for tests: `LAContext.setCredential(_, type: .smartCardPIN)`.
- Signing key 0x8E accepts both PSO CDS and INTERNAL AUTHENTICATE command forms (6982 without PIN);
  an actual signature still needs the user's 6-digit PIN.

## Builder's calls (made without the user; they can override)
ObjC for the card library and extension (consistent with the existing code), SwiftUI + Observation for the app,
deployment target macOS 27 with deprecations as errors (user requirement: no legacy APIs), bundle IDs
`com.alxrxs.rocei.connector[.extension]` (user requirement), branch `native-ctk-driver`, no commits until asked.
