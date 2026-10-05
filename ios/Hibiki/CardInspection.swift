/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Kaede Akino
 */

import Foundation
import Observation

/// Read-only presentation state; never changes the NFC usage record.
@MainActor @Observable
final class CardInspection {
    private(set) var transport: CardTransport = .usb
    private(set) var info: CardInfo?
    private(set) var isReading = false
    private(set) var error: String?
    private var usbInfo: CardInfo?
    private var nfcAvailable = false
    private var visible = false
    private var active = true
    private var usbPresent = false
    private var generation = UUID()
    @ObservationIgnored private var task: Task<Void, Never>?
    @ObservationIgnored private var read: ((CardTransport) async throws -> CardInfo)?

    func appear(usbPresent: Bool, active: Bool, read: @escaping (CardTransport) async throws -> CardInfo) {
        self.read = read
        self.usbPresent = usbPresent
        self.active = active
        visible = true
    }

    func disappear() {
        visible = false
        cancel()
    }

    func setActive(_ value: Bool) {
        guard active != value else { return }
        active = value
        if !value { cancel() }
    }

    func usbChanged(_ present: Bool) {
        guard usbPresent != present else { return }
        usbPresent = present
        if !present, transport == .usb { cancel() }
    }

    func usbRemoved() {
        if transport == .usb { cancel() }
    }

    func setNFCAvailable(_ available: Bool) {
        nfcAvailable = available
        if !available, transport == .nfc { select(.usb) }
    }

    func select(_ transport: CardTransport) {
        guard transport != .nfc || nfcAvailable else { return }
        guard self.transport != transport else { return }
        cancel()
        self.transport = transport
        info = transport == .usb ? usbInfo : nil
    }

    func refresh() {
        guard visible, active, (transport != .nfc || nfcAvailable), let read else { return }
        let previous = task
        cancel()
        if transport == .nfc { info = nil }
        isReading = true
        let id = generation
        let mode = transport
        task = Task {
            // Cancellation must release the old reader before another read can begin.
            await previous?.value
            guard generation == id, !Task.isCancelled else { return }
            do {
                let result = try await read(mode)
                guard generation == id, !Task.isCancelled else { return }
                if mode == .usb { usbInfo = result }
                info = result
            } catch {
                guard generation == id, !Task.isCancelled else { return }
                if case MobileError.Cancelled = error { /* System NFC sheet was canceled. */ }
                else if error is CancellationError { /* No error for intentional cancellation. */ }
                else if case MobileError.Failed(let message) = error {
                    self.error = message == "card is in use" ? String(localized: "Security key is in use. Try again when the operation finishes.") : message
                } else { self.error = error.localizedDescription }
            }
            isReading = false
        }
    }

    func reset() {
        cancel()
        info = nil
        usbInfo = nil
    }

    private func cancel() {
        generation = UUID()
        task?.cancel()
        isReading = false
        error = nil
    }
}

enum PinentryLabel {
    static func display(_ value: String) -> String {
        var output = ""
        var iterator = value.makeIterator()
        while let character = iterator.next() {
            if character == "_" {
                if let next = iterator.next() { output.append(next) }
            } else { output.append(character) }
        }
        return output
    }
}

struct OpenPGPIdentity {
    let serial: String
    let version: String
    let manufacturer: String

    init?(aid: String) {
        guard aid.count == 32, aid.uppercased().hasPrefix("D27600012401"),
              aid.allSatisfy({ $0.isHexDigit }) else { return nil }
        let characters = Array(aid.uppercased())
        func field(_ range: Range<Int>) -> String { String(characters[range]) }
        serial = field(20..<28)
        manufacturer = field(16..<20)
        // OpenPGP version bytes use packed BCD, not a binary integer.
        let major = field(12..<14)
        let minor = field(14..<16)
        guard let majorNumber = Int(major), let minorNumber = Int(minor) else { return nil }
        version = "\(majorNumber).\(minorNumber)"
    }
}
