//
// ROCEIApp.swift
// RO CEI Connector
//
// The eID works without this app (the CryptoTokenKit extension is loaded by the system when the
// card is inserted). The app shows the card contents and manages PINs.
//
// SPDX-License-Identifier: AGPL-3.0-only
//

import SwiftUI

@main
struct ROCEIApp: App {
  private let model = CardModel()

  var body: some Scene {
    WindowGroup("RO CEI Connector") {
      ContentView().environment(model)
    }
    .windowResizability(.contentMinSize)
    .commands { CommandGroup(replacing: .newItem) {} }
  }
}
