//
// ContentView.swift
// RO CEI Connector
//
// SPDX-License-Identifier: AGPL-3.0-only
//

import AppKit
import SwiftUI
import Observation
import UniformTypeIdentifiers

enum Section: String, CaseIterable, Identifiable {
  case card, certificates, pin, personal
  var id: String { rawValue }
  var title: LocalizedStringResource {
    switch self {
    case .card: return "Card"
    case .certificates: return "Certificates"
    case .pin: return "PIN"
    case .personal: return "Personal data"
    }
  }
  var icon: String {
    switch self {
    case .card: return "cpu"
    case .certificates: return "key.fill"
    case .pin: return "lock.fill"
    case .personal: return "person.text.rectangle"
    }
  }
}

/// View-local state lives in @Observable objects owned by CardModel: SwiftUI's @State is a macro
/// whose plugin ships only with Xcode, and this project builds with the Command Line Tools.
@MainActor @Observable final class NavState { var section: Section? = .card }

@MainActor @Observable final class PINForm {
  var which: CEIPIN = .user
  var current = ""
  var new1 = ""
  var new2 = ""
  var busy = false
  var done: String?
  func clear() { current = ""; new1 = ""; new2 = "" }
}

@MainActor @Observable final class PersonalForm {
  var pin = ""
  var busy = false
}

struct ContentView: View {
  @Environment(CardModel.self) private var model
  var body: some View {
    @Bindable var nav = model.nav
    NavigationSplitView {
      List(Section.allCases, selection: $nav.section) { s in
        Label { Text(s.title) } icon: { Image(systemName: s.icon) }.tag(s)
      }
      .navigationSplitViewColumnWidth(min: 170, ideal: 190)
    } detail: {
      Group {
        switch model.state {
        case .ready:
          switch nav.section ?? .card {
          case .card: CardView()
          case .certificates: CertificatesView()
          case .pin: PINView()
          case .personal: PersonalDataView()
          }
        default:
          StatusView(state: model.state)
        }
      }
      .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
    .frame(minWidth: 720, minHeight: 480)
  }
}

struct StatusView: View {
  let state: CardState
  var body: some View {
    VStack(spacing: 12) {
      Spacer()
      switch state {
      case .noReader:
        Image(systemName: "externaldrive.badge.xmark").font(.system(size: 44))
        Text("Connect a smart card reader").font(.title3)
      case .noCard:
        Image(systemName: "creditcard").font(.system(size: 44))
        Text("Insert your identity card").font(.title3)
      case .reading:
        ProgressView()
        Text("Reading card…")
      case .unsupported(let why):
        Image(systemName: "exclamationmark.triangle").font(.system(size: 44)).foregroundStyle(.orange)
        Text(why).multilineTextAlignment(.center)
      case .ready:
        EmptyView()
      }
      Spacer()
    }
    .frame(maxWidth: .infinity)
    .padding()
  }
}

struct Row: View {
  let label: String
  let value: String
  var valueColor: Color = .primary

  /// Static label from the string catalog.
  init(label: LocalizedStringResource, value: String, valueColor: Color = .primary) {
    self.init(text: String(localized: label), value: value, valueColor: valueColor)
  }
  /// Label that is already localized (e.g. built by CardModel).
  init(text: String, value: String, valueColor: Color = .primary) {
    self.label = text
    self.value = value
    self.valueColor = valueColor
  }

  var body: some View {
    GridRow {
      Text(label).foregroundStyle(.secondary).gridColumnAlignment(.trailing)
      Text(value).foregroundStyle(valueColor).textSelection(.enabled)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
  }
}

func triesText(_ p: PINState?) -> (String, Color) {
  guard let p else { return (String(localized: "unknown"), .secondary) }
  if p.blocked { return (String(localized: "blocked"), .red) }
  if p.verified { return (String(localized: "verified — currently unlocked"), .green) }
  if p.triesLeft < 0 { return (String(localized: "unknown"), .secondary) }
  return (String(localized: "\(p.triesLeft) tries remaining"), p.triesLeft < 3 ? .orange : .primary)
}

struct CardView: View {
  @Environment(CardModel.self) private var model
  var body: some View {
    Form {
      SwiftUI.Section("Security device") {
        Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 8) {
          Row(label: "Reader", value: model.readerName ?? "–")
          Row(label: "Label", value: model.tokenInfo?.label ?? "–")
          Row(label: "Model", value: "ID-A (IDEMIA Cosmo X)")
          Row(label: "Manufacturer", value: model.tokenInfo?.manufacturer ?? "–")
          Row(label: "Serial number", value: model.tokenInfo?.serial ?? "–")
          Row(label: "Available to macOS",
              value: model.tokenRegistered ? String(localized: "Yes — usable in Safari and other apps")
                                           : String(localized: "Waiting for the system…"),
              valueColor: model.tokenRegistered ? .green : .secondary)
        }
      }
      SwiftUI.Section("Credentials") {
        Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 8) {
          ForEach(model.pins) { p in
            let t = triesText(p)
            Row(text: p.name, value: t.0, valueColor: t.1)
          }
        }
      }
    }
    .formStyle(.grouped)
    .toolbar { Button("Refresh") { model.reload() } }
  }
}

struct CertificatesView: View {
  @Environment(CardModel.self) private var model
  var body: some View {
    Form {
      ForEach(model.certificates) { c in
        SwiftUI.Section(c.title) {
          Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 8) {
            Row(label: "Subject", value: c.subject)
            Row(label: "Issuer", value: c.issuer)
            if let from = c.notValidBefore { Row(label: "Valid from", value: from.formatted(date: .long, time: .omitted)) }
            if let to = c.notValidAfter {
              Row(label: "Valid until", value: to.formatted(date: .long, time: .omitted),
                  valueColor: to < Date() ? .red : .primary)
            }
            Row(label: "Protected by", value: c.pinName)
            Row(label: "SHA-256", value: c.sha256).font(.system(.caption, design: .monospaced))
          }
          HStack {
            Spacer()
            Button("Export…") { export(c) }
          }
        }
      }
    }
    .formStyle(.grouped)
  }

  private func export(_ c: CertificateInfo) {
    let panel = NSSavePanel()
    panel.allowedContentTypes = [UTType(filenameExtension: "cer") ?? .data]
    panel.nameFieldStringValue = c.key == .signing ? "eID-signature.cer" : "eID-authentication.cer"
    if panel.runModal() == .OK, let url = panel.url {
      try? c.der.write(to: url)
    }
  }
}

struct PINView: View {
  @Environment(CardModel.self) private var model
  private var f: PINForm { model.pinForm }

  private var range: NSRange { CEICard.lengthRange(for: f.which) }
  private var minLen: Int { range.location }
  private var maxLen: Int { range.location + range.length - 1 }
  private func valid(_ s: String) -> Bool { s.count >= minLen && s.count <= maxLen && s.allSatisfy(\.isNumber) }
  private var canSubmit: Bool { valid(f.current) && valid(f.new1) && f.new1 == f.new2 && !f.busy && !(model.pinState(f.which)?.blocked ?? true) }

  var body: some View {
    @Bindable var f = model.pinForm
    Form {
      SwiftUI.Section("Change PIN") {
        Picker("PIN", selection: $f.which) {
          Text("PIN (authentication, personal data)").tag(CEIPIN.user)
          Text("Signature PIN").tag(CEIPIN.signature)
        }
        .onChange(of: f.which) { f.clear(); f.done = nil }
        let t = triesText(model.pinState(f.which))
        LabeledContent("Remaining tries") { Text(t.0).foregroundStyle(t.1) }
        Text("Enter your current PIN carefully. Each wrong attempt uses one try; after the last one the PIN is blocked and has to be unblocked with the PUK.")
          .font(.callout).foregroundStyle(.secondary)
        SecureField("Current PIN", text: $f.current)
        let newTitle: LocalizedStringKey = minLen == maxLen ? "New PIN (\(minLen) digits)" : "New PIN (\(minLen)–\(maxLen) digits)"
        SecureField(newTitle, text: $f.new1)
        SecureField("Confirm new PIN", text: $f.new2)
        if !f.new2.isEmpty && f.new1 != f.new2 { Text("The new PINs don't match.").foregroundStyle(.red) }
        HStack {
          if let d = f.done { Text(d).foregroundStyle(.green) }
          if let e = model.lastError { Text(e).foregroundStyle(.red) }
          Spacer()
          Button("Change") {
            f.busy = true
            f.done = nil
            Task {
              let ok = await model.changePIN(f.which, from: f.current, to: f.new1)
              f.busy = false
              f.clear()
              if ok { f.done = String(localized: "PIN changed.") }
            }
          }
          .disabled(!canSubmit)
          .keyboardShortcut(.defaultAction)
        }
      }
    }
    .formStyle(.grouped)
    .onAppear { model.lastError = nil }
  }
}

struct PersonalDataView: View {
  @Environment(CardModel.self) private var model
  var body: some View {
    @Bindable var f = model.personalForm
    Form {
      if let data = model.personalData {
        SwiftUI.Section("Card holder") {
          Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 8) {
            ForEach(Array(data.fields.enumerated()), id: \.offset) { _, item in Row(text: item.label, value: item.value) }
            ForEach(Array(data.residences.enumerated()), id: \.offset) { _, item in Row(text: item.label, value: item.value) }
          }
          HStack {
            Spacer()
            Button("Hide") { model.forgetPersonalData() }
          }
        }
      } else {
        SwiftUI.Section("Personal data") {
          Text("Reading the personal data requires your 4-digit PIN.")
            .foregroundStyle(.secondary)
          let t = triesText(model.pinState(.user))
          LabeledContent("Remaining tries") { Text(t.0).foregroundStyle(t.1) }
          SecureField("PIN", text: $f.pin)
          HStack {
            if let e = model.lastError { Text(e).foregroundStyle(.red) }
            Spacer()
            if f.busy { ProgressView().controlSize(.small) }
            Button("Read") {
              f.busy = true
              let p = f.pin
              f.pin = ""
              Task {
                await model.readPersonalData(pin: p)
                f.busy = false
              }
            }
            .disabled(f.pin.count < 4 || f.busy || (model.pinState(.user)?.blocked ?? true))
            .keyboardShortcut(.defaultAction)
          }
        }
      }
    }
    .formStyle(.grouped)
    .onAppear { model.lastError = nil }
  }
}
