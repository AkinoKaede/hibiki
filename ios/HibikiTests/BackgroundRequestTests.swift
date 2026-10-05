/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Kaede Akino
 */

import XCTest
import SwiftUI
import UserNotifications
@testable import Hibiki

@MainActor
final class BackgroundRequestTests: XCTestCase {
    private func fixture() -> (AppModel, BackgroundClient, TestBackgroundRuntime, TestNotifications, TestCardHardware) {
        let runtime = TestBackgroundRuntime()
        let notifications = TestNotifications()
        let hardware = TestCardHardware()
        let model = AppModel(defaults: UserDefaults(suiteName: "background-tests-\(UUID().uuidString)")!, resetRelayStorage: {}, nfcCapability: { false }, backgroundRuntime: runtime, notifications: notifications, hardware: hardware)
        let client = BackgroundClient(noHandle: .init())
        model.client = client
        model.initialized = true
        model.connection = "online"
        return (model, client, runtime, notifications, hardware)
    }
    private func settle(_ condition: () -> Bool) async {
        for _ in 0..<100 {
            if condition() { return }
            try? await Task.sleep(for: .milliseconds(10))
        }
        XCTFail("State did not settle")
    }
    private func prompt(_ token: String, kind: PromptKind = .pin) -> PinPrompt {
        PinPrompt(token: token, session: "session", request: 1, channel: "PRIVATE CHANNEL", deviceName: "PRIVATE DEVICE", deviceId: "peer", kind: kind, title: "PRIVATE TITLE", description: "SECRET DESCRIPTION", label: "PIN", error: "", repeat: "", repeatError: "", ok: "", cancel: "", notOk: "", timeoutSeconds: 120)
    }
    private func channel(_ id: String, active: Bool = true) -> ChannelInfo {
        ChannelInfo(id: id, name: id, active: active, revision: 1, members: [])
    }
    private func join(_ id: String, channel: String) -> PendingInfo {
        PendingInfo(id: id, channel: channel, device: DeviceInfo(id: "peer", name: "PRIVATE DEVICE", words: "", online: true, approvedBy: nil, approverName: nil, canRevoke: false, revokedByServer: false, reverseRevokeAvailableAt: nil, revocationSubtree: []))
    }

    func testUSBEventsSurviveBackgroundAndIgnoreStaleSnapshots() async {
        let (model, core, _, _, hardware) = fixture()
        await hardware.setUSB(true)
        await model.activate()
        XCTAssertTrue(model.usbPresent)
        let original = core.read { $0.usbConnections.last! }
        await hardware.setUSB(false)
        await hardware.setUSB(true)
        await settle { core.read { $0.usbConnections.count } == 3 }
        XCTAssertNotEqual(core.read { $0.usbConnections.last! }, original)
        await hardware.emitUSB(USBState(revision: 0, connections: []))
        await Task.yield()
        XCTAssertTrue(model.usbPresent)
        model.sceneChanged(.background)
        await hardware.setUSB(false)
        await settle { !model.usbPresent }
        XCTAssertEqual(core.read { $0.usbConnections.last! }, [])
        model.sceneChanged(.active)
        await model.activate()
        XCTAssertFalse(model.usbPresent)
        let count = core.read { $0.usbConnections.count }
        await model.syncUSBState()
        XCTAssertEqual(core.read { $0.usbConnections.count }, count)
        await model.disconnectRelay()
        await hardware.setUSB(true)
        await Task.yield()
        XCTAssertFalse(model.usbPresent)
    }

    func testBackgroundKeepsConnectionAndPromptsButHidesPresentation() async {
        let (model, core, runtime, notices, _) = fixture()
        core.update { $0.tokens = ["pin"] }
        model.handle(.prompt(prompt: prompt("pin")), core: core)
        model.sceneChanged(.inactive)
        XCTAssertNotNil(model.currentPrompt)
        XCTAssertTrue(runtime.handlers.isEmpty)
        model.sceneChanged(.background)
        XCTAssertEqual(core.read { $0.stops }, 0)
        XCTAssertNil(model.currentPrompt)
        XCTAssertEqual(model.prompts.count, 1)
        XCTAssertEqual(notices.sent, [.operation("pin")])
        model.handle(.prompt(prompt: prompt("pin")), core: core)
        XCTAssertEqual(notices.sent.count, 1)
        model.sceneChanged(.active)
        await settle { core.read { $0.starts } == 1 }
        XCTAssertEqual(model.currentPrompt?.token, "pin")
        XCTAssertTrue(notices.active.isEmpty)
        XCTAssertEqual(runtime.ended, [1])
        await model.disconnectRelay()
    }

    func testExpirationIsSynchronousAndOldCallbackCannotStopNewConnection() async {
        let (model, core, runtime, _, _) = fixture()
        model.sceneChanged(.background)
        runtime.handlers[1]?()
        XCTAssertEqual(core.read { $0.stopRequests }, 1)
        XCTAssertEqual(model.connection, "offline")
        XCTAssertEqual(runtime.ended, [1])
        model.sceneChanged(.active)
        await settle { core.read { $0.starts } == 1 }
        runtime.handlers[1]?()
        XCTAssertEqual(core.read { $0.stopRequests }, 1)
        model.sceneChanged(.background)
        runtime.handlers[1]?()
        XCTAssertEqual(core.read { $0.stopRequests }, 1)
        runtime.handlers[2]?()
        XCTAssertEqual(core.read { $0.stopRequests }, 2)
        await model.disconnectRelay()
    }

    func testDeniedBackgroundTimeStopsImmediately() async {
        let (model, core, runtime, _, _) = fixture()
        runtime.denied = true
        model.sceneChanged(.background)
        XCTAssertEqual(core.read { $0.stopRequests }, 1)
        XCTAssertTrue(runtime.ended.isEmpty)
        await model.disconnectRelay()
    }

    func testRapidTransitionsAndDisconnectIgnoreOldCallbacks() async {
        let (model, core, runtime, notices, _) = fixture()
        model.sceneChanged(.background)
        model.sceneChanged(.active)
        model.sceneChanged(.background)
        model.sceneChanged(.active)
        await settle { core.read { $0.starts } == 1 }
        XCTAssertEqual(runtime.ended, [1, 2])
        await model.disconnectRelay()
        let count = core.read { $0.stopRequests }
        runtime.handlers.values.forEach { $0() }
        XCTAssertEqual(core.read { $0.stopRequests }, count)
        XCTAssertNil(model.client)
        XCTAssertTrue(notices.active.isEmpty)
        XCTAssertTrue(model.pendingJoins.isEmpty)
    }

    func testBackgroundRequestsNotifyOnceAndCancellationRemovesThem() async {
        let (model, core, _, notices, _) = fixture()
        core.update { $0.tokens = ["pin", "card"] }
        model.sceneChanged(.background)
        model.handle(.prompt(prompt: prompt("pin")), core: core)
        model.handle(.prompt(prompt: prompt("pin")), core: core)
        model.handle(.prompt(prompt: prompt("card", kind: .cardNfc)), core: core)
        XCTAssertEqual(notices.sent, [.operation("pin"), .operation("card")])
        model.handle(.cancelled(token: "pin"), core: core)
        XCTAssertFalse(notices.active.contains(.operation("pin")))
        XCTAssertEqual(model.prompts.map(\.token), ["card"])
        await model.disconnectRelay()
    }

    func testDeferredReaderDoesNotOpenInBackgroundOrAfterExpiry() async {
        let (model, core, _, notices, hardware) = fixture()
        core.update { $0.tokens = ["open"] }
        model.sceneChanged(.background)
        model.handle(.cardOpen(token: "open", connection: "reader", transport: .nfc), core: core)
        let backgroundOpens = await hardware.opened
        XCTAssertTrue(backgroundOpens.isEmpty)
        XCTAssertEqual(notices.sent, [.operation("open")])
        core.update { $0.tokens.remove("open") }
        model.handle(.cancelled(token: "open"), core: core)
        model.sceneChanged(.active)
        await settle { core.read { $0.starts } == 1 }
        let expiredOpens = await hardware.opened
        XCTAssertTrue(expiredOpens.isEmpty)
        await model.disconnectRelay()
    }

    func testDeferredReaderContinuesOnlyOnceOnForeground() async {
        let (model, core, _, _, hardware) = fixture()
        core.update { $0.tokens = ["open"] }
        model.sceneChanged(.background)
        model.handle(.cardOpen(token: "open", connection: "reader", transport: .nfc), core: core)
        model.sceneChanged(.active)
        await settle { core.read { $0.answers.contains("open") } }
        model.sceneChanged(.active)
        let opens = await hardware.opened
        XCTAssertEqual(opens, ["open"])
        await model.disconnectRelay()
    }

    func testReaderWaitsUntilPriorBackgroundCleanupFinishes() async {
        let (model, core, _, _, hardware) = fixture()
        await hardware.holdClose()
        model.sceneChanged(.background)
        for _ in 0..<100 {
            if await hardware.isClosing { break }
            try? await Task.sleep(for: .milliseconds(10))
        }
        model.sceneChanged(.active)
        core.update { $0.tokens = ["new-reader"] }
        model.handle(.cardOpen(token: "new-reader", connection: "reader", transport: .nfc), core: core)
        let beforeCleanup = await hardware.opened
        XCTAssertTrue(beforeCleanup.isEmpty)
        await hardware.releaseClose()
        await settle { core.read { $0.answers.contains("new-reader") } }
        let afterCleanup = await hardware.opened
        XCTAssertEqual(afterCleanup, ["new-reader"])
        await model.disconnectRelay()
    }

    func testActiveHardwareWorkIsCancelledOnBackgroundAndNotReplayed() async {
        let (model, core, _, _, hardware) = fixture()
        await hardware.holdOpen()
        core.update { $0.tokens = ["active-reader"] }
        model.handle(.cardOpen(token: "active-reader", connection: "reader", transport: .nfc), core: core)
        for _ in 0..<100 {
            if await hardware.opened.count == 1 { break }
            try? await Task.sleep(for: .milliseconds(10))
        }
        let initialOpens = await hardware.opened
        XCTAssertEqual(initialOpens, ["active-reader"])
        model.sceneChanged(.background)
        XCTAssertEqual(core.read { $0.failed }, ["active-reader"])
        XCTAssertFalse(core.requestIsPending(token: "active-reader"))
        model.sceneChanged(.active)
        await settle { core.read { $0.starts } == 1 }
        let opens = await hardware.opened
        XCTAssertEqual(opens, ["active-reader"])
        XCTAssertTrue(core.read { $0.answers.isEmpty })
        await model.disconnectRelay()
    }

    func testBackgroundTransmitIsCancelledAndNeverReplayed() async {
        let (model, core, _, _, hardware) = fixture()
        core.update { $0.tokens = ["transmit"] }
        model.sceneChanged(.background)
        model.handle(.cardTransmit(token: "transmit", connection: "reader", command: Data([0, 1])), core: core)
        XCTAssertEqual(core.read { $0.failed }, ["transmit"])
        model.sceneChanged(.active)
        await settle { core.read { $0.starts } == 1 }
        let transmits = await hardware.transmitted
        XCTAssertTrue(transmits.isEmpty)
        await model.disconnectRelay()
    }

    func testJoinBaselineMultipleChannelsDeduplicationAndWithdrawal() async {
        let (model, core, _, notices, _) = fixture()
        core.update { state in
            state.channels = [channel("a"), channel("b")]
            state.joins = ["a": [join("old", channel: "a")]]
        }
        await model.refreshPendingRequests()
        XCTAssertTrue(notices.sent.isEmpty)
        model.sceneChanged(.background)
        core.update { state in
            state.joins["a"]?.append(join("new", channel: "a"))
            state.joins["b"] = [join("new", channel: "b")]
        }
        await model.refreshPendingRequests()
        await model.refreshPendingRequests()
        XCTAssertEqual(Set(notices.sent), [.join(channel: "a", request: "new"), .join(channel: "b", request: "new")])
        XCTAssertEqual(notices.sent.count, 2)
        core.update { $0.joins["a"] = [] }
        await model.refreshPendingRequests()
        XCTAssertFalse(notices.active.contains(.join(channel: "a", request: "new")))
        core.update { $0.channels = [channel("a"), channel("b", active: false)] }
        await model.refreshPendingRequests()
        XCTAssertNil(model.pendingJoins["b"])
        XCTAssertTrue(notices.active.isEmpty)
        await model.disconnectRelay()
    }

    func testFailedJoinQueryPreservesSnapshotAndDoesNotRenotify() async {
        let (model, core, _, notices, _) = fixture()
        core.update { $0.channels = [channel("a")]; $0.joins["a"] = [join("new", channel: "a")] }
        model.sceneChanged(.background)
        await model.refreshPendingRequests()
        core.update { $0.failPending = true }
        await model.refreshPendingRequests()
        XCTAssertEqual(model.pendingJoins["a"]?.count, 1)
        XCTAssertEqual(notices.active.count, 1)
        core.update { $0.failPending = false }
        await model.refreshPendingRequests()
        XCTAssertEqual(notices.sent.count, 1)
        await model.disconnectRelay()
    }

    func testNotificationOpensExactPromptAndExpiredPromptDoesNotExecute() async {
        let (model, core, _, notices, _) = fixture()
        core.update { $0.tokens = ["first", "second"] }
        model.handle(.prompt(prompt: prompt("first")), core: core)
        model.handle(.prompt(prompt: prompt("second")), core: core)
        notices.onOpen?(.operation("second"))
        await settle { model.currentPrompt?.token == "second" }
        XCTAssertEqual(model.selectedTab, "status")
        notices.onOpen?(.operation("expired"))
        await settle { model.unavailableNotification != nil }
        XCTAssertTrue(core.read { $0.answers.isEmpty })
        XCTAssertNil(model.currentPrompt)
        model.unavailableNotification = nil
        XCTAssertNotNil(model.currentPrompt)
        await model.disconnectRelay()
    }

    func testJoinNotificationNavigatesToExactApprovalWithoutApproving() async {
        let (model, core, _, notices, _) = fixture()
        core.update { $0.joins["channel"] = [join("request", channel: "channel")] }
        notices.onOpen?(.join(channel: "channel", request: "request"))
        await settle { model.channelPath.count == 2 }
        XCTAssertEqual(model.selectedTab, "channels")
        XCTAssertEqual(model.channelPath, [.channel("channel"), .approval(channel: "channel", request: "request")])
        XCTAssertEqual(core.read { $0.approvals }, 0)
        core.update { $0.joins["channel"] = [] }
        notices.onOpen?(.join(channel: "channel", request: "request"))
        await settle { model.unavailableNotification != nil }
        XCTAssertEqual(model.channelPath, [.channel("channel")])
        XCTAssertEqual(core.read { $0.approvals }, 0)
        await model.disconnectRelay()
    }

    func testJoinClickWaitsForForegroundAndConnection() async {
        let (model, core, _, notices, _) = fixture()
        core.update { $0.joins["channel"] = [join("request", channel: "channel")] }
        model.sceneChanged(.background)
        notices.onOpen?(.join(channel: "channel", request: "request"))
        model.connection = "offline"
        model.sceneChanged(.active)
        await settle { model.selectedTab == "channels" }
        XCTAssertEqual(model.channelPath, [.channel("channel")])
        model.handle(.connection(state: "online"), core: core)
        await settle { model.channelPath.count == 2 }
        await model.disconnectRelay()
    }

    func testDeniedNotificationsDoNotStopConnectionOrPrompts() async {
        let (model, core, _, notices, _) = fixture()
        notices.permission = .denied
        await model.activate()
        await model.refreshNotificationAuthorization()
        XCTAssertEqual(model.notificationAuthorization, .denied)
        XCTAssertEqual(core.read { $0.stops }, 0)
        core.update { $0.tokens = ["pin"] }
        model.handle(.prompt(prompt: prompt("pin")), core: core)
        XCTAssertNotNil(model.currentPrompt)
        await model.disconnectRelay()
    }

    func testNotificationContentContainsOnlyTypeAndOpaqueRoute() throws {
        let target = RequestNoticeTarget.join(channel: "opaque-channel-id", request: "opaque-request-id")
        let content = SystemRequestNotifications.content(for: target, kind: .join)
        XCTAssertEqual(content.title, "Hibiki")
        XCTAssertEqual(content.userInfo.count, 1)
        XCTAssertEqual(try JSONDecoder().decode(RequestNoticeTarget.self, from: XCTUnwrap(content.userInfo["route"] as? Data)), target)
        for kind in [RequestNoticeKind.password, .confirmation, .message, .card, .join] {
            let text = SystemRequestNotifications.content(for: target, kind: kind).body
            for secret in ["PRIVATE DEVICE", "PRIVATE CHANNEL", "SECRET DESCRIPTION", "opaque-channel-id", "opaque-request-id"] { XCTAssertFalse(text.contains(secret)) }
        }
    }
}

@MainActor
private final class TestBackgroundRuntime: BackgroundRuntime {
    var denied = false
    var handlers: [Int: @MainActor () -> Void] = [:]
    var ended: [Int] = []
    func begin(expiration: @escaping @MainActor () -> Void) -> Int? {
        if denied { return nil }
        let id = handlers.count + 1
        handlers[id] = expiration
        return id
    }
    func end(_ identifier: Int) { ended.append(identifier) }
}

@MainActor
private final class TestNotifications: RequestNotifications {
    var onOpen: (@MainActor (RequestNoticeTarget) -> Void)?
    var permission = NoticeAuthorization.allowed
    var sent: [RequestNoticeTarget] = []
    var active: Set<RequestNoticeTarget> = []
    func authorization(requestIfNeeded: Bool) async -> NoticeAuthorization { permission }
    func send(_ target: RequestNoticeTarget, kind: RequestNoticeKind) { sent.append(target); active.insert(target) }
    func remove(_ target: RequestNoticeTarget) { active.remove(target) }
    func clearOperations() { active = active.filter { !$0.isOperation } }
    func clearAll() { active.removeAll() }
}

private actor TestCardHardware: CardHardwareAccess {
    var opened: [String] = []
    var transmitted: [String] = []
    private var insertions = USBInsertions()
    private var usbContinuation: AsyncStream<USBState>.Continuation?
    func usbState() -> USBState { insertions.state }
    func usbEvents() -> AsyncStream<USBState> {
        AsyncStream { usbContinuation = $0; $0.yield(insertions.state) }
    }
    func setUSB(_ present: Bool) {
        insertions.update(name: "test-reader", present: present)
        usbContinuation?.yield(insertions.state)
    }
    func emitUSB(_ state: USBState) { usbContinuation?.yield(state) }
    private var holdingOpen = false
    func holdOpen() { holdingOpen = true }
    func open(id: String, token: String, transport: CardTransport) async throws -> Data {
        opened.append(token)
        if holdingOpen { try await Task.sleep(for: .seconds(30)) }
        return Data()
    }
    func transmit(id: String, token: String, command: Data) -> Data { transmitted.append(token); return Data([0x90, 0]) }
    func cancel(token: String) {}
    func close(id: String) {}
    private var holdingClose = false
    private var closeContinuation: CheckedContinuation<Void, Never>?
    var isClosing: Bool { closeContinuation != nil }
    func holdClose() { holdingClose = true }
    func releaseClose() {
        holdingClose = false
        closeContinuation?.resume()
        closeContinuation = nil
    }
    func closeAll() async {
        if holdingClose { await withCheckedContinuation { closeContinuation = $0 } }
    }
}

private final class BackgroundClient: MobileClient, @unchecked Sendable {
    struct State {
        var starts = 0
        var stops = 0
        var stopRequests = 0
        var approvals = 0
        var tokens: Set<String> = []
        var answers: [String] = []
        var failed: [String] = []
        var channels: [ChannelInfo] = []
        var joins: [String: [PendingInfo]] = [:]
        var failPending = false
        var usbConnections: [[String]] = []
    }
    private let lock = NSLock()
    private var state = State()
    func update(_ body: (inout State) -> Void) { lock.withLock { body(&state) } }
    func read<T>(_ body: (State) -> T) -> T { lock.withLock { body(state) } }
    override func start() async throws { update { $0.starts += 1 } }
    override func stop() async { update { $0.stops += 1; $0.tokens.removeAll() } }
    override func requestStop() { update { $0.stopRequests += 1; $0.tokens.removeAll() } }
    override func requestIsPending(token: String) -> Bool { read { $0.tokens.contains(token) } }
    override func respond(token: String, data: Data, accepted: Bool) throws { update { $0.answers.append(token); $0.tokens.remove(token) } }
    override func failNativeRequest(token: String, message: String, canceled: Bool) throws { update { $0.failed.append(token); $0.tokens.remove(token) } }
    override func cancelRequest(token: String) throws { update { $0.tokens.remove(token) } }
    override func nfcCard() -> CardInfo? { nil }
    override func setNfcAvailable(available: Bool) {}
    override func setServices(pinentry: Bool, card: Bool) {}
    override func usbPresent(present: Bool) {}
    override func usbConnections(connections: [String]) { update { $0.usbConnections.append(connections) } }
    override func channels() async throws -> [ChannelInfo] { read { $0.channels } }
    override func allowsChannelCreation() async throws -> Bool { true }
    override func pending(channel: String) async throws -> [PendingInfo] {
        if read({ $0.failPending }) { throw URLError(.networkConnectionLost) }
        return read { $0.joins[channel] ?? [] }
    }
    override func approve(channel: String, requestId: String) async throws { update { $0.approvals += 1 } }
}
