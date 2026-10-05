/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Kaede Akino
 */

import XCTest
import SwiftUI
@testable import Hibiki

@MainActor
final class CardInspectionTests: XCTestCase {
    func testRecordIsVolatileAndIndependentOfInspection() async throws {
        let suite = "hibiki-nfc-record-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let model = AppModel(defaults: defaults, nfcCapability: { true })
        let recorded = card("recorded", .nfc)
        model.recordedNFCCard = recorded
        model.cardInspection.setNFCAvailable(true)
        model.cardInspection.appear(usbPresent: false, active: true) { _ in self.card("viewed", .nfc) }
        model.cardInspection.select(.nfc)
        model.cardInspection.refresh()
        try await eventually { model.cardInspection.info != nil }
        XCTAssertEqual(model.recordedNFCCard, recorded)
        model.clearNFCRecord()
        XCTAssertNil(model.recordedNFCCard)
        XCTAssertEqual(model.cardInspection.info?.serial, "viewed")
        model.recordedNFCCard = recorded
        model.sceneChanged(.inactive)
        XCTAssertEqual(model.recordedNFCCard, recorded)
        model.sceneChanged(.background)
        model.sceneChanged(.active)
        XCTAssertEqual(model.recordedNFCCard, recorded)
        XCTAssertNil(AppModel(defaults: defaults, nfcCapability: { true }).recordedNFCCard)
        model.cardInspection.disappear()
    }

    func testOnlyGnuPGInsertionDescriptionMatches() {
        XCTAssertEqual(cardInsertionNumber(description: "Please insert the card with serial number:\n\n  0005 00001234\n  "), "0005 00001234")
        XCTAssertNil(cardInsertionNumber(description: "Confirm deleting this key?"))
        XCTAssertNil(cardInsertionNumber(description: "Please insert the card with serial number: invalid"))
    }

    private func card(_ serial: String, _ transport: CardTransport) -> CardInfo {
        CardInfo(serial: serial, transport: transport, keys: [])
    }

    private func eventually(_ predicate: () -> Bool, file: StaticString = #filePath, line: UInt = #line) async throws {
        for _ in 0..<100 {
            if predicate() { return }
            try await Task.sleep(for: .milliseconds(10))
        }
        XCTFail("State did not settle", file: file, line: line)
    }

    func testUSBOnlyReadsOnExplicitRefresh() async throws {
        let state = CardInspection()
        state.setNFCAvailable(true)
        var reads = 0
        let read: (CardTransport) async throws -> CardInfo = { mode in
            reads += 1
            return self.card("USB-\(reads)", mode)
        }
        state.appear(usbPresent: true, active: true, read: read)
        state.usbChanged(false)
        state.usbChanged(true)
        state.setActive(false)
        state.setActive(true)
        state.select(.nfc)
        state.select(.usb)
        state.disappear()
        state.appear(usbPresent: true, active: true, read: read)
        XCTAssertFalse(state.isReading)
        await Task.yield()
        XCTAssertEqual(reads, 0)
        state.refresh()
        try await eventually { !state.isReading }
        XCTAssertEqual(reads, 1)
        XCTAssertEqual(state.info?.serial, "USB-1")
        state.usbChanged(false)
        state.usbChanged(true)
        XCTAssertFalse(state.isReading)
        XCTAssertEqual(state.info?.serial, "USB-1")
        state.refresh()
        try await eventually { !state.isReading }
        XCTAssertEqual(reads, 2)
        XCTAssertEqual(state.info?.serial, "USB-2")
        state.disappear()
    }

    func testUSBManualReadDoesNotRequirePresenceAndSurvivesInsertionNotification() async throws {
        let state = CardInspection()
        var pending: CheckedContinuation<CardInfo, Error>?
        state.appear(usbPresent: false, active: true) { _ in
            try await withCheckedThrowingContinuation { pending = $0 }
        }
        state.refresh()
        try await eventually { pending != nil }
        state.usbChanged(true)
        XCTAssertTrue(state.isReading)
        pending?.resume(returning: card("USB", .usb))
        try await eventually { !state.isReading }
        XCTAssertEqual(state.info?.serial, "USB")
        state.usbChanged(false)
        state.appear(usbPresent: false, active: true) { _ in throw HardwareError.cardNotPresent }
        state.refresh()
        try await eventually { !state.isReading }
        XCTAssertNotNil(state.error)
        XCTAssertEqual(state.info?.serial, "USB")
        state.disappear()
    }

    func testUSBInsertionIdentityChangesOnRapidReplugAndPreservesOtherReaders() {
        var insertions = USBInsertions()
        XCTAssertFalse(insertions.update(name: "one", present: false))
        insertions.update(name: "one", present: true)
        insertions.update(name: "two", present: true)
        let first = insertions.state
        let other = insertions.identities["two"]
        XCTAssertFalse(insertions.update(name: "one", present: true))
        XCTAssertEqual(insertions.state, first)
        insertions.update(name: "one", present: false)
        insertions.update(name: "one", present: true)
        XCTAssertEqual(insertions.state.revision, first.revision + 2)
        XCTAssertNotEqual(insertions.state.connections, first.connections)
        XCTAssertEqual(insertions.identities["two"], other)
        insertions.update(name: "one", present: false)
        XCTAssertEqual(insertions.state.connections, [other!])
    }

    func testUSBCacheSurvivesFailureCancellationAndTransportChanges() async throws {
        let state = CardInspection()
        state.setNFCAvailable(true)
        var reads = 0
        var pending: CheckedContinuation<CardInfo, Error>?
        state.appear(usbPresent: true, active: true) { mode in
            reads += 1
            if reads == 2 { throw MobileError.Failed(message: "Reader unavailable") }
            if reads == 3 { return try await withCheckedThrowingContinuation { pending = $0 } }
            return self.card("USB-\(reads)", mode)
        }
        state.refresh()
        try await eventually { !state.isReading }
        state.refresh()
        try await eventually { !state.isReading }
        XCTAssertEqual(state.error, "Reader unavailable")
        XCTAssertEqual(state.info?.serial, "USB-1")
        state.refresh()
        try await eventually { pending != nil }
        state.usbChanged(false)
        pending?.resume(returning: card("Removed key", .usb))
        state.disappear()
        state.setActive(false)
        state.setActive(true)
        state.select(.nfc)
        XCTAssertNil(state.info)
        state.select(.usb)
        XCTAssertEqual(state.info?.serial, "USB-1")
        state.appear(usbPresent: true, active: true) { mode in self.card("New key", mode) }
        XCTAssertEqual(state.info?.serial, "USB-1")
        XCTAssertFalse(state.isReading)
        state.refresh()
        try await eventually { !state.isReading }
        XCTAssertEqual(state.info?.serial, "New key")
        state.reset()
        XCTAssertNil(state.info)
        state.select(.nfc)
        state.usbChanged(false)
        state.select(.usb)
        XCTAssertNil(state.info)
        state.disappear()
    }

    func testSwitchFromNFCToUSBWaitsForCancellationAndDiscardsLateResult() async throws {
        let state = CardInspection()
        state.setNFCAvailable(true)
        var reads: [CardTransport] = []
        var nfc: CheckedContinuation<CardInfo, Error>?
        state.appear(usbPresent: true, active: true) { mode in
            reads.append(mode)
            if mode == .nfc {
                return try await withCheckedThrowingContinuation { nfc = $0 }
            }
            return self.card("USB", mode)
        }
        state.refresh()
        try await eventually { state.info != nil }
        state.select(.nfc)
        XCTAssertNil(state.info)
        XCTAssertEqual(reads, [.usb])
        state.refresh()
        try await eventually { nfc != nil }
        state.select(.usb)
        XCTAssertFalse(state.isReading)
        state.refresh()
        XCTAssertTrue(state.isReading)
        XCTAssertEqual(state.info?.serial, "USB")
        XCTAssertEqual(reads, [.usb, .nfc])
        nfc?.resume(returning: card("Stale NFC", .nfc))
        try await eventually { !state.isReading }
        XCTAssertEqual(state.info?.serial, "USB")
        XCTAssertEqual(reads, [.usb, .nfc, .usb])
        state.disappear()
    }

    func testLeavingAndBackgroundingInvalidatePendingReads() async throws {
        for background in [false, true] {
            let state = CardInspection()
            state.setNFCAvailable(true)
            var pending: CheckedContinuation<CardInfo, Error>?
            state.appear(usbPresent: true, active: true) { _ in
                try await withCheckedThrowingContinuation { pending = $0 }
            }
            state.refresh()
            try await eventually { pending != nil }
            if background { state.setActive(false) } else { state.disappear() }
            XCTAssertFalse(state.isReading)
            pending?.resume(returning: card("Stale", .usb))
            // Queue a new reader behind the old one to deterministically wait for its completion.
            state.appear(usbPresent: true, active: true) { mode in self.card("New", mode) }
            state.refresh()
            try await eventually { !state.isReading }
            XCTAssertEqual(state.info?.serial, "New")
            XCTAssertNil(state.error)
            state.disappear()
        }
    }

    func testNFCIsExplicitAndUserCancellationIsSilentButFailuresAllowRetry() async throws {
        let state = CardInspection()
        state.setNFCAvailable(true)
        var reads = 0
        state.appear(usbPresent: false, active: true) { mode in
            reads += 1
            if reads == 1 { throw MobileError.Cancelled }
            if reads == 2 { throw MobileError.Failed(message: "Reader unavailable") }
            return self.card("NFC", mode)
        }
        state.select(.nfc)
        XCTAssertEqual(reads, 0)
        state.refresh()
        try await eventually { !state.isReading }
        XCTAssertNil(state.error)
        state.refresh()
        try await eventually { !state.isReading }
        XCTAssertEqual(state.error, "Reader unavailable")
        state.refresh()
        try await eventually { state.info != nil }
        XCTAssertEqual(state.info?.transport, .nfc)
        XCTAssertNil(state.error)
        state.disappear()
    }

    func testPinentryMnemonicLabelsPreserveEscapedUnderscoresAndUnicode() {
        for (input, expected) in [("_OK", "OK"), ("_Cancel", "Cancel"), ("Save _As", "Save As"), ("A__B", "A_B"), ("___OK", "_OK"), ("_确认", "确认"), ("OK", "OK"), ("", "")] {
            XCTAssertEqual(PinentryLabel.display(input), expected)
        }
    }

    func testOpenPGPIdentityUsesActualAIDAndRejectsMalformedData() throws {
        let identity = try XCTUnwrap(OpenPGPIdentity(aid: "D2760001240103040005000012340000"))
        XCTAssertEqual(identity.serial, "00001234")
        XCTAssertEqual(identity.version, "3.4")
        XCTAssertEqual(identity.manufacturer, "0005")
        for invalid in ["", "one", "D27600012401030G0005000012340000", "A2760001240103040005000012340000"] {
            XCTAssertNil(OpenPGPIdentity(aid: invalid))
        }
    }

    /// Simulator attachments allow review of long identifiers, translations and native forms.
    func testRenderSecurityKeyScreens() async throws {
        let suite = "hibiki-render-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let model = AppModel(defaults: defaults, nfcCapability: { true })
        let info = CardInfo(serial: "D2760001240103040005000012340000", transport: .usb, keys: [
            CardKey(slot: 1, algorithm: "rsa4096", fingerprint: String(repeating: "A1", count: 20), keygrip: String(repeating: "B2", count: 20), publicKey: Data(), createdAt: 1_700_000_000)
        ])
        model.recordedNFCCard = info
        model.device = DeviceInfo(id: "test-device", name: "iPhone", words: "public verification words", online: false, approvedBy: nil, approverName: nil, canRevoke: false, revokedByServer: false, reverseRevokeAvailableAt: nil, revocationSubtree: [])
        for language in ["en", "zh-Hans"] {
            model.cardInspection.select(.usb)
            try await render(NavigationStack { CardView(model: model) }, name: "USB-\(language)", language: language)
            // Each reader preview owns its lifecycle, including delayed onDisappear callbacks.
            let nfcModel = AppModel(defaults: defaults, nfcCapability: { true })
            nfcModel.recordedNFCCard = info
            nfcModel.refreshHardwareCapabilities()
            nfcModel.cardInspection.appear(usbPresent: false, active: true) { _ in info }
            nfcModel.cardInspection.select(.nfc)
            nfcModel.cardInspection.refresh()
            try await eventually { nfcModel.cardInspection.info != nil }
            try await render(NavigationStack { CardView(model: nfcModel) }, name: "NFC-\(language)", language: language)
            try await render(NavigationStack { SettingsView(model: model) }, name: "About-\(language)", language: language)
        }
        XCTAssertNotNil(Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString"))
        let prompt = PinPrompt(token: "preview", session: "preview", request: 1, channel: "Personal", deviceName: "Mac", deviceId: "test-device", kind: .confirm, title: "", description: "Confirm this request", label: "", error: "", repeat: "", repeatError: "", ok: "_OK", cancel: "_Cancel", notOk: "_No", timeoutSeconds: 60)
        try await render(PinView(prompt: prompt, model: model), name: "PIN-buttons", language: "en")
        model.cardInspection.disappear()
    }

    func testRenderPingAndVerificationWords() async throws {
        let ping = DevicePing()
        var index = 0
        let values: [UInt64?] = [70_000, 381_000, nil, 60_000, 120_000, 40_000, 210_000]
        ping.start(measure: { _ in
            defer { index += 1 }
            return DevicePingReport(setupMicros: 541_000, roundTripsMicros: [values[index]])
        }, pause: { if index == values.count { ping.stop() } })
        try await eventually { ping.samples.count == values.count }
        for language in ["en", "zh-Hans"] {
            for dark in [false, true] {
                let screen = NavigationStack {
                    Form {
                        HStack { Text("Status"); Spacer(); DeviceStatus(online: true, available: true) }
                        DevicePingSection(ping: ping, canPing: true) {}
                        Section("Public-Key Verification Words") {
                            VerificationWords(words: (1...24).map { "word\($0)" }.joined(separator: " "))
                        }
                    }.navigationTitle("Work Mac")
                }.environment(\.colorScheme, dark ? .dark : .light)
                try await render(screen, name: "Ping-\(language)-\(dark ? "dark" : "light")", language: language)
            }
        }
    }

    func testRenderDeviceListAtLargeType() async throws {
        let model = AppModel(nfcCapability: { false })
        model.connection = "online"
        let words = (1...24).map { "word\($0)" }.joined(separator: " ")
        let local = DeviceInfo(id: "local", name: "iPhone 16 Pro", words: words, online: true, approvedBy: nil, approverName: nil, canRevoke: false, revokedByServer: false, reverseRevokeAvailableAt: nil, revocationSubtree: [])
        let remote = DeviceInfo(id: "remote", name: "Kaede-MacBook-Pro", words: words, online: true, approvedBy: nil, approverName: nil, canRevoke: false, revokedByServer: false, reverseRevokeAvailableAt: nil, revocationSubtree: [])
        model.device = local
        model.channels = [ChannelInfo(id: "channel", name: "personal", active: true, revision: 1, members: [local, remote])]
        let list = NavigationStack { ChannelView(channelID: "channel", model: model) }
        try await render(list, name: "Members", language: "en")
        try await render(list.environment(\.dynamicTypeSize, .accessibility1), name: "Members-large-type", language: "en")
        try await render(NavigationStack { MemberDetailView(channelID: "channel", deviceID: "remote", model: model) }, name: "Device-details", language: "en")
    }

    private func render<Content: View>(_ content: Content, name: String, language: String) async throws {
        let scene = try XCTUnwrap(UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }.first)
        let previous = scene.windows.first(where: \.isKeyWindow)
        let window = UIWindow(windowScene: scene)
        window.frame = scene.coordinateSpace.bounds
        window.rootViewController = UIHostingController(rootView: content.environment(\.locale, Locale(identifier: language)))
        window.makeKeyAndVisible()
        defer { window.isHidden = true; previous?.makeKey() }
        try await Task.sleep(for: .milliseconds(300))
        window.layoutIfNeeded()
        let image = UIGraphicsImageRenderer(bounds: window.bounds).image { _ in
            XCTAssertTrue(window.drawHierarchy(in: window.bounds, afterScreenUpdates: true))
        }
        let directory = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0].appendingPathComponent("HibikiUIReview")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try image.pngData()?.write(to: directory.appendingPathComponent(name + ".png"))
        let attachment = XCTAttachment(image: image)
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }
}
