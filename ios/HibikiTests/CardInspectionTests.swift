import XCTest
import SwiftUI
@testable import Hibiki

@MainActor
final class CardInspectionTests: XCTestCase {
    func testCapabilityChangesHideNFCWithoutChangingRegistrations() async throws {
        var available = false
        let model = AppModel(nfcCapability: { available })
        let entry = RegisteredCard(card: card("NFC only", .nfc), name: "NFC key", usbEnabled: false, nfcEnabled: true)
        model.registeredCards = [entry]
        model.refreshHardwareCapabilities()
        XCTAssertTrue(model.usableCards.isEmpty)
        model.cardInspection.select(.nfc)
        XCTAssertEqual(model.cardInspection.transport, .usb)
        available = true
        model.refreshHardwareCapabilities()
        XCTAssertEqual(model.usableCards.count, 1)
        model.cardInspection.select(.nfc)
        XCTAssertEqual(model.cardInspection.transport, .nfc)
        available = false
        model.refreshHardwareCapabilities()
        XCTAssertEqual(model.cardInspection.transport, .usb)
        XCTAssertTrue(model.registeredCards[0].nfcEnabled)
        XCTAssertEqual(entry.connections(nfcAvailable: false), String(localized: "Unavailable on This Device"))
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

    func testUSBReadsOncePerInsertionAndClearsOnRemoval() async throws {
        let state = CardInspection()
        state.setNFCAvailable(true)
        var reads = 0
        state.appear(usbPresent: true, active: true) { mode in
            reads += 1
            return self.card("USB", mode)
        }
        try await eventually { state.info != nil }
        XCTAssertEqual(reads, 1)
        for _ in 0..<5 { state.usbChanged(true) }
        XCTAssertEqual(reads, 1)
        state.usbChanged(false)
        XCTAssertNil(state.info)
        state.usbChanged(true)
        try await eventually { reads == 2 && !state.isReading }
        state.refresh()
        try await eventually { reads == 3 && !state.isReading }
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
        try await eventually { state.info != nil }
        state.select(.nfc)
        XCTAssertNil(state.info)
        XCTAssertEqual(reads, [.usb])
        state.refresh()
        try await eventually { nfc != nil }
        state.select(.usb)
        XCTAssertTrue(state.isReading)
        XCTAssertNil(state.info)
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
            try await eventually { pending != nil }
            if background { state.setActive(false) } else { state.disappear() }
            XCTAssertFalse(state.isReading)
            pending?.resume(returning: card("Stale", .usb))
            // Queue a new reader behind the old one to deterministically wait for its completion.
            state.appear(usbPresent: true, active: true) { mode in self.card("New", mode) }
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
        let entry = RegisteredCard(card: info, name: "Daily security key", usbEnabled: true, nfcEnabled: true)
        model.registeredCards = [entry]
        model.device = DeviceInfo(id: "test-device", name: "iPhone", words: "public verification words", online: false, approvedBy: nil, approverName: nil, canRevoke: false, revokedByServer: false, reverseRevokeAvailableAt: nil, revocationSubtree: [])
        for language in ["en", "zh-Hans"] {
            model.cardInspection.select(.usb)
            try await render(NavigationStack { CardView(model: model) }, name: "USB-\(language)", language: language)
            // Each reader preview owns its lifecycle, including delayed onDisappear callbacks.
            let nfcModel = AppModel(defaults: defaults, nfcCapability: { true })
            nfcModel.registeredCards = [entry]
            nfcModel.refreshHardwareCapabilities()
            nfcModel.cardInspection.appear(usbPresent: false, active: true) { _ in info }
            nfcModel.cardInspection.select(.nfc)
            nfcModel.cardInspection.refresh()
            try await eventually { nfcModel.cardInspection.info != nil }
            try await render(NavigationStack { CardView(model: nfcModel) }, name: "NFC-\(language)", language: language)
            try await render(EditRegisteredCardView(entry: entry, model: model), name: "Edit-\(language)", language: language)
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
