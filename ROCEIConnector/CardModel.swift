//
// CardModel.swift
// RO CEI Connector
//
// Watches smart card readers and reads the Romanian eID through CEICard (native APDUs).
// All card I/O runs on a private serial queue inside exclusive CryptoTokenKit sessions.
//
// SPDX-License-Identifier: AGPL-3.0-only
//

import CryptoKit
@preconcurrency import CryptoTokenKit
import Foundation
import Observation
import Security

struct PINState: Identifiable, Equatable {
  let ref: CEIPIN
  var triesLeft: Int
  var blocked: Bool
  /// The card reports the PIN as already verified (e.g. the eID driver just used it), in which
  /// case it doesn't report a try counter.
  var verified: Bool
  var id: UInt8 { ref.rawValue }
  var name: String { CEICard.displayName(for: ref) }
}

struct CertificateInfo: Identifiable {
  let key: CEIKey
  let der: Data
  var id: Int { key.rawValue }
  var title: String { key == .signing ? String(localized: "Signature certificate") : String(localized: "Authentication certificate") }
  var pinName: String { key == .signing ? String(localized: "Signature PIN (6 digits)") : String(localized: "PIN (4 digits)") }

  private var certificate: SecCertificate? { SecCertificateCreateWithData(nil, der as CFData) }

  var subject: String {
    guard let c = certificate else { return "?" }
    return (SecCertificateCopySubjectSummary(c) as String?) ?? "?"
  }

  var issuer: String {
    guard let c = certificate, let data = SecCertificateCopyNormalizedIssuerSequence(c) as Data? else { return "?" }
    return CertificateInfo.commonName(inDERName: data) ?? "?"
  }

  var notValidAfter: Date? { CertificateInfo.validity(of: der)?.1 }
  var notValidBefore: Date? { CertificateInfo.validity(of: der)?.0 }

  var sha256: String {
    SHA256.hash(data: der).map { String(format: "%02X", $0) }.joined(separator: ":")
  }

  /// Extracts the last CN (2.5.4.3) value from a DER Name.
  static func commonName(inDERName name: Data) -> String? {
    let oid: [UInt8] = [0x06, 0x03, 0x55, 0x04, 0x03]
    let bytes = [UInt8](name)
    var result: String?
    var i = 0
    while i + oid.count + 2 < bytes.count {
      if Array(bytes[i..<i + oid.count]) == oid {
        let len = Int(bytes[i + oid.count + 1])
        let start = i + oid.count + 2
        if start + len <= bytes.count {
          result = String(decoding: bytes[start..<start + len], as: UTF8.self)
        }
      }
      i += 1
    }
    return result
  }

  /// notBefore / notAfter from the TBSCertificate (UTCTime or GeneralizedTime).
  static func validity(of der: Data) -> (Date, Date)? {
    let b = [UInt8](der)
    func parseTime(_ at: Int) -> (Date, Int)? {
      guard at + 2 <= b.count else { return nil }
      let tag = b[at], len = Int(b[at + 1])
      guard (tag == 0x17 || tag == 0x18), at + 2 + len <= b.count else { return nil }
      let digits = Array(String(decoding: b[(at + 2)..<(at + 2 + len)], as: UTF8.self).utf8.prefix { $0 != UInt8(ascii: "Z") })
      func num(_ r: Range<Int>) -> Int? { r.upperBound <= digits.count ? Int(String(decoding: digits[r], as: UTF8.self)) : nil }
      let yearLen = tag == 0x17 ? 2 : 4
      guard var year = num(0..<yearLen), let mo = num(yearLen..<yearLen + 2), let d = num(yearLen + 2..<yearLen + 4),
            let h = num(yearLen + 4..<yearLen + 6), let mi = num(yearLen + 6..<yearLen + 8),
            let sec = num(yearLen + 8..<yearLen + 10) else { return nil }
      if tag == 0x17 { year += year < 50 ? 2000 : 1900 }  // RFC 5280 UTCTime
      var cal = Calendar(identifier: .gregorian)
      cal.timeZone = .gmt
      guard let date = cal.date(from: DateComponents(year: year, month: mo, day: d, hour: h, minute: mi, second: sec))
      else { return nil }
      return (date, at + 2 + len)
    }
    // Find the first SEQUENCE containing two consecutive time values.
    var i = 0
    while i + 4 < b.count {
      if b[i] == 0x30, let (from, next) = parseTime(i + 2), let (to, _) = parseTime(next) {
        return (from, to)
      }
      i += 1
    }
    return nil
  }
}

struct PersonalData: Sendable {
  struct Field: Sendable { let label: String; let value: String }
  var fields: [Field]
  var residences: [Field]
}

/// Sendable snapshot of the PKCS#15 TokenInfo.
struct TokenSummary: Sendable {
  let label: String
  let manufacturer: String
  let serial: String
}

/// TKSmartCard isn't annotated for Sendable. Every use of the wrapped card happens on CardModel's
/// private serial queue, one request at a time, so moving the handle onto that queue is safe.
private struct CardHandle: @unchecked Sendable {
  let card: TKSmartCard
}

enum CardState: Equatable {
  case noReader
  case noCard
  case reading
  case unsupported(String)
  case ready
}

@MainActor
@Observable
final class CardModel {
  private(set) var state: CardState = .noReader
  private(set) var readerName: String?
  private(set) var tokenInfo: TokenSummary?
  private(set) var certificates: [CertificateInfo] = []
  private(set) var pins: [PINState] = []
  private(set) var personalData: PersonalData?
  private(set) var tokenRegistered = false
  var lastError: String?

  @ObservationIgnored private let queue = DispatchQueue(label: "ro.cei.card")
  @ObservationIgnored private var slotObservation: NSKeyValueObservation?
  @ObservationIgnored private var stateObservation: NSKeyValueObservation?
  @ObservationIgnored private var currentSlot: TKSmartCardSlot?
  @ObservationIgnored private let tokenWatcher = TKTokenWatcher()

  /// View-local form state (kept here because SwiftUI's @State macro needs Xcode's plugin).
  let nav = NavState()
  let pinForm = PINForm()
  let personalForm = PersonalForm()

  init() {
    start()
  }

  private func start() {
    guard let manager = TKSmartCardSlotManager.default else {
      state = .unsupported(String(localized: "Smart card access is not available to this app."))
      return
    }
    // System callbacks arrive on arbitrary queues: keep them nonisolated (@Sendable) and hop to the
    // main actor explicitly, otherwise Swift 6's isolation check traps.
    slotObservation = manager.observe(\.slotNames, options: [.initial, .new]) { @Sendable [weak self] mgr, _ in
      let names = mgr.slotNames
      Task { @MainActor in self?.slotsChanged(names) }
    }
    tokenWatcher.setInsertionHandler { @Sendable [weak self] _ in
      Task { @MainActor in self?.refreshTokenRegistration() }
    }
  }

  private func slotsChanged(_ names: [String]) {
    guard let name = names.first else {
      currentSlot = nil
      stateObservation = nil
      readerName = nil
      clearCard()
      state = .noReader
      return
    }
    if name == readerName, currentSlot != nil { return }
    readerName = name
    attach(TKSmartCardSlotManager.default?.slotNamed(name))
  }

  private func attach(_ slot: TKSmartCardSlot?) {
    currentSlot = slot
    guard let slot else {
      state = .noReader
      return
    }
    stateObservation = slot.observe(\.state, options: [.initial, .new]) { @Sendable [weak self] s, _ in
      let state = s.state
      Task { @MainActor in self?.slotStateChanged(state) }
    }
  }

  private func slotStateChanged(_ s: TKSmartCardSlot.State) {
    switch s {
    case .validCard:
      reload()
    case .empty, .missing:
      clearCard()
      state = .noCard
    case .probing:
      state = .reading
    default:
      clearCard()
      state = .unsupported(String(localized: "The card in the reader could not be read."))
    }
  }

  private func clearCard() {
    tokenInfo = nil
    certificates = []
    pins = []
    personalData = nil
    tokenRegistered = false
  }

  private func refreshTokenRegistration() {
    tokenRegistered = tokenWatcher.tokenIDs.contains { $0.hasPrefix("com.alxrxs.rocei.connector.extension") }
  }

  /// Runs `body` with a CEICard inside an exclusive card session, off the main thread.
  private func withCard<T: Sendable>(_ body: @escaping @Sendable (CEICard) throws -> T) async throws -> T {
    guard let slot = currentSlot, let sc = slot.makeSmartCard() else {
      throw NSError(domain: CEICardErrorDomain, code: CEICardError.transport.rawValue,
                    userInfo: [NSLocalizedDescriptionKey: String(localized: "No card in the reader")])
    }
    let handle = CardHandle(card: sc)
    return try await withCheckedThrowingContinuation { (cont: CheckedContinuation<T, Error>) in
      queue.async {
        do {
          let card = handle.card
          cont.resume(returning: try card.withSession { try body(CEICard(transport: card)) })
        } catch {
          cont.resume(throwing: error)
        }
      }
    }
  }

  func reload() {
    state = .reading
    lastError = nil
    Task {
      do {
        let (info, certs, pinStates) = try await withCard { card -> (TokenSummary, [CertificateInfo], [PINState]) in
          let ti = try card.readTokenInfo()
          let info = TokenSummary(label: ti.label, manufacturer: ti.manufacturer, serial: ti.shortSerial)
          var certs: [CertificateInfo] = []
          for key in [CEIKey.authentication, .signing] {
            if let der = try? card.readCertificate(for: key) { certs.append(CertificateInfo(key: key, der: der)) }
          }
          let pins = try CardModel.readPINStates(card)
          return (info, certs, pins)
        }
        tokenInfo = info
        certificates = certs
        pins = pinStates
        state = .ready
        refreshTokenRegistration()
      } catch {
        let ns = error as NSError
        if ns.domain == CEICardErrorDomain, ns.code == CEICardError.notThisCard.rawValue {
          state = .unsupported(String(localized: "This is not a Romanian electronic identity card."))
        } else {
          state = .unsupported(error.localizedDescription)
        }
      }
    }
  }

  nonisolated private static func readPINStates(_ card: CEICard) throws -> [PINState] {
    try [CEIPIN.user, .userPUK, .signature, .signaturePUK].map { ref in
      var st = CEIPINStatus()
      try card.getStatusOf(ref, status: &st)
      return PINState(ref: ref, triesLeft: st.triesLeft, blocked: st.blocked.boolValue, verified: st.verified.boolValue)
    }
  }

  func pinState(_ ref: CEIPIN) -> PINState? { pins.first { $0.ref == ref } }

  /// Verifies the user PIN (one VERIFY) and reads the personal data.
  func readPersonalData(pin: String) async {
    lastError = nil
    do {
      let data = try await withCard { card -> (PersonalData, [PINState]) in
        try card.verifyPIN(.user, value: pin)
        let p = CardModel.present(try card.readPersonalData())
        return (p, try CardModel.readPINStates(card))
      }
      personalData = data.0
      pins = data.1
    } catch {
      lastError = error.localizedDescription
      await refreshPINs()
    }
  }

  func forgetPersonalData() { personalData = nil }

  /// Sends exactly one CHANGE REFERENCE DATA.
  func changePIN(_ ref: CEIPIN, from old: String, to new: String) async -> Bool {
    lastError = nil
    do {
      try await withCard { card in try card.change(ref, from: old, to: new) }
      await refreshPINs()
      return true
    } catch {
      lastError = error.localizedDescription
      await refreshPINs()
      return false
    }
  }

  func refreshPINs() async {
    if let p = try? await withCard({ try CardModel.readPINStates($0) }) { pins = p }
  }

  nonisolated private static func present(_ p: CEIPersonalData) -> PersonalData {
    func date(_ c: DateComponents?) -> String? {
      guard let c, let d = c.day, let m = c.month, let y = c.year else { return nil }
      return String(format: "%02d.%02d.%04d", d, m, y)
    }
    var f: [PersonalData.Field] = []
    func add(_ k: String, _ v: String?) { if let v, !v.isEmpty { f.append(.init(label: k, value: v)) } }
    add(String(localized: "Last name"), p.lastName)
    add(String(localized: "First name"), p.firstName)
    add(String(localized: "Sex"), p.gender)
    add(String(localized: "Date of birth"), date(p.dateOfBirth))
    add(String(localized: "Place of birth"), p.placeOfBirth)
    add(String(localized: "Personal numeric code (CNP)"), p.personalNumber)
    add(String(localized: "Citizenship"), p.citizenship)
    add(String(localized: "Document number"), p.documentNumber)
    add(String(localized: "Issued"), date(p.issueDate))
    add(String(localized: "Expires"), date(p.expiryDate))
    add(String(localized: "Issued by"), p.issuingAuthority)
    add(String(localized: "Domicile"), p.permanentAddress)
    var r: [PersonalData.Field] = []
    for (title, list) in [(String(localized: "Temporary residence"), p.temporaryResidences),
                         (String(localized: "Residence abroad"), p.foreignResidences)] {
      for res in list where (res.address ?? "").isEmpty == false {
        let period = [date(res.startDate), date(res.endDate)].compactMap { $0 }.joined(separator: " – ")
        r.append(.init(label: title, value: res.address! + (period.isEmpty ? "" : "\n\(period)")))
      }
    }
    return PersonalData(fields: f, residences: r)
  }
}
