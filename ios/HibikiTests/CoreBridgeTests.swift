import XCTest
@testable import Hibiki

final class CoreBridgeTests: XCTestCase {
    @MainActor
    func testPendingPairingSurvivesRestartAndCanBeCleared() throws {
        let suite = "hibiki-tests-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let model = AppModel(defaults: defaults)
        XCTAssertNil(model.allowChannelCreation)
        model.rememberPairing(JoinInfo(verification: "", channel: "channel", request: "request"))
        let restored = AppModel(defaults: defaults)
        XCTAssertEqual(restored.pairing?.request, "request")
        restored.rememberPairing(nil)
        XCTAssertNil(AppModel(defaults: defaults).pairing)
        restored.rememberPairing(JoinInfo(verification: "", channel: "claimed", request: ""))
        XCTAssertNil(restored.pairing)
    }

    func testServerAddressCandidatesPreserveExplicitSchemePortPathAndQuery() throws {
        for (input, expected) in [
            ("hibiki.example.com", ["wss://hibiki.example.com/hibiki", "ws://hibiki.example.com/hibiki"]),
            ("  wss://hibiki.example.com/\n", ["wss://hibiki.example.com/hibiki"]),
            ("ws://localhost:7749", ["ws://localhost:7749/hibiki"]),
            ("localhost:7749", ["wss://localhost:7749/hibiki", "ws://localhost:7749/hibiki"]),
            ("[::1]:7749/", ["wss://[::1]:7749/hibiki", "ws://[::1]:7749/hibiki"]),
            ("ws://[::1]:7749/", ["ws://[::1]:7749/hibiki"]),
            ("wss://hibiki.example.com/hibiki", ["wss://hibiki.example.com/hibiki"]),
            ("WSS://hibiki.example.com/custom?region=one", ["wss://hibiki.example.com/custom?region=one"]),
            ("hibiki.example.com/custom?region=one", ["wss://hibiki.example.com/custom?region=one", "ws://hibiki.example.com/custom?region=one"]),
            ("wss://hibiki.example.com?region=one", ["wss://hibiki.example.com/hibiki?region=one"])
        ] { XCTAssertEqual(try AppModel.serverURLs(from: input), expected) }
        for invalid in ["", "  ", "not a host", "https://example.com", "wss://", "ws://localhost:99999", "wss://user:pass@example.com", "wss://example.com/#fragment"] {
            XCTAssertThrowsError(try AppModel.serverURLs(from: invalid), invalid)
        }
    }
    @MainActor
    func testServerDiscoveryPrefersWSSAndStopsOnSuccess() async throws {
        var attempts: [String] = []
        let selected = try await AppModel.discoverServer(from: "example.com") { attempts.append($0) }
        XCTAssertEqual(selected, "wss://example.com/hibiki")
        XCTAssertEqual(attempts, [selected])
    }
    @MainActor
    func testServerDiscoveryFallsBackToWSAfterFailedWSS() async throws {
        var attempts: [String] = []
        let selected = try await AppModel.discoverServer(from: "localhost:7749/custom?q=1") {
            attempts.append($0)
            if $0.hasPrefix("wss:") { throw URLError(.secureConnectionFailed) }
        }
        XCTAssertEqual(selected, "ws://localhost:7749/custom?q=1")
        XCTAssertEqual(attempts, ["wss://localhost:7749/custom?q=1", selected])
    }
    @MainActor
    func testServerDiscoveryNeverChangesExplicitProtocol() async throws {
        for scheme in ["wss", "ws"] {
            var attempts: [String] = []
            do {
                _ = try await AppModel.discoverServer(from: "\(scheme)://example.com") {
                    attempts.append($0)
                    throw URLError(.cannotConnectToHost)
                }
                XCTFail("An unreachable explicit address must fail")
            } catch { XCTAssertEqual(attempts, ["\(scheme)://example.com/hibiki"]) }
        }
    }
    @MainActor
    func testServerDiscoveryReportsBothFailures() async throws {
        var attempts: [String] = []
        do {
            _ = try await AppModel.discoverServer(from: "example.com") {
                attempts.append($0)
                throw URLError(.cannotConnectToHost)
            }
            XCTFail("Both failed probes must fail setup")
        } catch {
            XCTAssertEqual(attempts.count, 2)
            for attempt in attempts { XCTAssertTrue(error.localizedDescription.contains(attempt)) }
        }
    }
    @MainActor
    func testServerDiscoveryDoesNotFallbackAfterCancellation() async throws {
        var attempts: [String] = []
        do {
            _ = try await AppModel.discoverServer(from: "example.com") {
                attempts.append($0)
                throw CancellationError()
            }
            XCTFail("Canceled discovery must not select a server")
        } catch is CancellationError {
            XCTAssertEqual(attempts, ["wss://example.com/hibiki"])
        } catch { XCTFail("Expected cancellation: \(error)") }
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
        XCTAssertTrue(model.pinEnabled)
        XCTAssertTrue(model.cardEnabled)
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
    func testRelayResetRemovesRetiredCardsAndTrustAndReplayState() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let removed = ["config/client.toml", "state/session", "cache/item", "runtime/lock", "data/channels/example/FORKED", "data/channels/example/trust.bin", "data/operations/request", "data/cards.bin", "data/nfc-cards.bin"]
        let retained = ["data/unrelated.bin"]
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
    @MainActor
    func testServicesDefaultToEnabledAndPreserveSavedChoices() throws {
        let suite = "hibiki-tests-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        for pin in [nil, false, true] as [Bool?] {
            for card in [nil, false, true] as [Bool?] {
                defaults.removePersistentDomain(forName: suite)
                if let pin { defaults.set(pin, forKey: "pinEnabled") }
                if let card { defaults.set(card, forKey: "cardEnabled") }
                let model = AppModel(defaults: defaults)
                XCTAssertEqual(model.pinEnabled, pin ?? true)
                XCTAssertEqual(model.cardEnabled, card ?? true)
                model.updateServices()
                let reopened = AppModel(defaults: defaults)
                XCTAssertEqual(reopened.pinEnabled, model.pinEnabled)
                XCTAssertEqual(reopened.cardEnabled, model.cardEnabled)
            }
        }
    }
    func testIdentitySurvivesReopening() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let identity = try createIdentity(name: "iPhone test")
        let first = try MobileClient(directory: directory.path, server: "wss://example.com/hibiki", identity: identity, skipTlsCertificateValidation: false)
        let second = try MobileClient(directory: directory.path, server: "wss://example.com/hibiki", identity: identity, skipTlsCertificateValidation: false)
        XCTAssertEqual(try first.device().id, try second.device().id)
        XCTAssertEqual(try first.device().words.split(separator: " ").count, 24)
        XCTAssertNil(first.nfcCard())
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
