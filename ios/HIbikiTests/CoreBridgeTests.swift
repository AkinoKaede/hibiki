import XCTest
@testable import HIbiki

final class CoreBridgeTests: XCTestCase {
    func testRelayAddressExpandsOnlyMissingSchemeAndRootPath() throws {
        for (input, expected) in [
            ("hibiki.example.com", "wss://hibiki.example.com/hibiki"),
            ("  wss://hibiki.example.com/\n", "wss://hibiki.example.com/hibiki"),
            ("ws://localhost:7749", "ws://localhost:7749/hibiki"),
            ("localhost:7749", "wss://localhost:7749/hibiki"),
            ("ws://[::1]:7749/", "ws://[::1]:7749/hibiki"),
            ("wss://hibiki.example.com/hibiki", "wss://hibiki.example.com/hibiki"),
            ("wss://hibiki.example.com/custom?region=one", "wss://hibiki.example.com/custom?region=one"),
            ("wss://hibiki.example.com?region=one", "wss://hibiki.example.com/hibiki?region=one")
        ] { XCTAssertEqual(try AppModel.relayURL(from: input), expected) }
        for invalid in ["", "  ", "not a host", "https://example.com", "wss://", "ws://localhost:99999", "wss://user:pass@example.com", "wss://example.com/#fragment"] {
            XCTAssertThrowsError(try AppModel.relayURL(from: invalid), invalid)
        }
    }
    @MainActor
    func testRelayStartsEmptyAndKeepsAnExplicitlySavedAddress() throws {
        let suite = "hibiki-tests-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        XCTAssertEqual(AppModel(defaults: defaults).server, "")
        defaults.set("wss://example.com/custom", forKey: "server")
        XCTAssertEqual(AppModel(defaults: defaults).server, "wss://example.com/custom")
    }
    @MainActor
    func testOfflineDisconnectClearsSetupAndDoesNotRestoreOldRelay() async throws {
        let suite = "hibiki-tests-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set("ws://127.0.0.1:1/hibiki", forKey: "server")
        defaults.set("My iPhone", forKey: "deviceName")
        for key in ["skipTLSCertificateValidation", "pinEnabled", "cardEnabled"] { defaults.set(true, forKey: key) }
        var resetCount = 0
        let model = AppModel(defaults: defaults, resetRelayStorage: {
            XCTAssertTrue(defaults.bool(forKey: "relayResetPending"))
            XCTAssertNil(defaults.string(forKey: "server"))
            resetCount += 1
        })
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let core = try MobileClient(directory: root.path, server: model.server, identity: createIdentity(name: model.name), skipTlsCertificateValidation: false)
        model.client = core
        model.device = try core.device()
        model.initialized = true
        model.connection = "offline"
        await model.activate()
        model.sceneChanged(.active)
        await model.disconnectRelay()
        XCTAssertEqual(resetCount, 1)
        XCTAssertFalse(model.initialized)
        XCTAssertEqual(model.server, "")
        XCTAssertFalse(model.busy)
        XCTAssertNil(model.client)
        XCTAssertNil(model.device)
        XCTAssertTrue(model.channels.isEmpty)
        XCTAssertNil(model.pairing)
        XCTAssertTrue(model.prompts.isEmpty)
        XCTAssertFalse(model.pinEnabled)
        XCTAssertFalse(model.cardEnabled)
        XCTAssertFalse(model.skipTLSCertificateValidation)
        XCTAssertEqual(model.name, "My iPhone")
        XCTAssertNil(defaults.object(forKey: "relayResetPending"))
        let reopened = AppModel(defaults: defaults)
        await reopened.restore()
        XCTAssertFalse(reopened.initialized)
        XCTAssertEqual(reopened.server, "")
        XCTAssertNil(reopened.client)
    }
    @MainActor
    func testInterruptedDisconnectRetriesCleanupBeforeRestore() async throws {
        let suite = "hibiki-tests-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set("ws://127.0.0.1:1/hibiki", forKey: "server")
        let model = AppModel(defaults: defaults, resetRelayStorage: { throw CocoaError(.fileWriteNoPermission) })
        model.initialized = true
        await model.disconnectRelay()
        XCTAssertTrue(defaults.bool(forKey: "relayResetPending"))
        XCTAssertFalse(model.initialized)
        XCTAssertNotNil(model.error)
        var reset = false
        let reopened = AppModel(defaults: defaults, resetRelayStorage: { reset = true })
        await reopened.restore()
        XCTAssertTrue(reset)
        XCTAssertNil(defaults.object(forKey: "relayResetPending"))
        XCTAssertFalse(reopened.initialized)
        XCTAssertNil(reopened.client)
    }
    func testRelayResetPreservesCardRegistrationsAndRemovesTrustAndReplayState() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let removed = ["config/client.toml", "state/session", "cache/item", "runtime/lock", "data/channels/example/FORKED", "data/channels/example/trust.bin", "data/operations/request"]
        let retained = ["data/cards.bin", "data/card.bin"]
        for path in removed + retained {
            let url = root.appendingPathComponent(path)
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try Data(path.utf8).write(to: url)
        }
        try SecureStorage.removeRelayFiles(in: root)
        try SecureStorage.removeRelayFiles(in: root) // Interrupted resets can be retried.
        for path in removed { XCTAssertFalse(FileManager.default.fileExists(atPath: root.appendingPathComponent(path).path)) }
        for path in retained { XCTAssertEqual(try Data(contentsOf: root.appendingPathComponent(path)), Data(path.utf8)) }
    }
    func testOnboardingRejectsAnInvalidRelay() async throws {
        let identity = try createIdentity(name: "test")
        do {
            try await checkRelay(server: "https://example.com", identity: identity, skipTlsCertificateValidation: false)
            XCTFail("A non-WebSocket relay must not pass onboarding")
        } catch {}
    }
    func testIdentitySurvivesReopeningAndServicesStartDisabled() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let identity = try createIdentity(name: "iPhone test")
        let first = try MobileClient(directory: directory.path, server: "wss://example.com/hibiki", identity: identity, skipTlsCertificateValidation: false)
        let second = try MobileClient(directory: directory.path, server: "wss://example.com/hibiki", identity: identity, skipTlsCertificateValidation: false)
        XCTAssertEqual(try first.device().id, try second.device().id)
        XCTAssertEqual(try first.device().words.split(separator: " ").count, 24)
        XCTAssertNil(first.selectedCard())
        XCTAssertFalse(first.requestIsPending(token: "expired"))
        XCTAssertThrowsError(try first.respond(token: "expired", data: Data("PIN".utf8), accepted: true))
    }
    func testPlaintextAllowedWithCertificateValidationEnabled() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let identity = try createIdentity(name: "test")
        XCTAssertNoThrow(try MobileClient(directory: directory.path, server: "ws://localhost:7749/hibiki", identity: identity, skipTlsCertificateValidation: false))
    }
    @MainActor
    func testInactiveSystemSheetDoesNotBackgroundApp() {
        let model = AppModel()
        model.foreground = true
        model.sceneChanged(.inactive)
        XCTAssertTrue(model.foreground)
        model.sceneChanged(.background)
        XCTAssertFalse(model.foreground)
    }
    func testInvalidIdentityFailsClosed() {
        XCTAssertThrowsError(try MobileClient(directory: "/tmp/hibiki-invalid", server: "wss://example.com/hibiki", identity: Data([1, 2, 3]), skipTlsCertificateValidation: false))
    }
}
