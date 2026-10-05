import SwiftUI

@main
struct HibikiApp: App {
    @State private var model = initialModel()
    @Environment(\.scenePhase) private var scenePhase
    var body: some Scene {
        WindowGroup {
            RootView(model: model)
                .task {
                    #if DEBUG
                    if CommandLine.arguments.contains("--ui-nfc-order-fixture") || CommandLine.arguments.contains("--ui-members-fixture") || CommandLine.arguments.contains("--ui-pin-fixture") { return }
                    #endif
                    await model.restore()
                }
                .onChange(of: scenePhase) { _, phase in
                    #if DEBUG
                    if CommandLine.arguments.contains("--ui-nfc-order-fixture") || CommandLine.arguments.contains("--ui-invitations-fixture") { return }
                    #endif
                    model.sceneChanged(phase)
                }
        }
    }
    @MainActor private static func initialModel() -> AppModel {
        #if DEBUG
        if CommandLine.arguments.contains("--ui-nfc-order-fixture") {
            let model = AppModel(defaults: UserDefaults(suiteName: "hibiki-ui-nfc-order-fixture")!)
            do { try model.configureNFCOrderFixture() } catch { model.show(error) }
            return model
        }
        // UI-only fixture: no client, saved identity, network or service execution.
        if CommandLine.arguments.contains("--ui-pin-fixture") {
            let model = AppModel(defaults: UserDefaults(suiteName: "hibiki-ui-pin-fixture")!, nfcCapability: { CommandLine.arguments.contains("--ui-nfc") })
            model.initialized = true
            model.prompts = [PinPrompt(token: "ui-pin", session: "ui-session", request: 1, channel: "UI Test Channel", deviceName: "Work Mac", deviceId: String(repeating: "b", count: 64), kind: .pin, title: "Hibiki Request", description: "Please enter the PIN for your security key.", label: "PIN", error: "", repeat: "", repeatError: "", ok: "OK", cancel: "", notOk: "", timeoutSeconds: 120)]
            if CommandLine.arguments.contains("--ui-nfc") {
                model.recordedNFCCard = CardInfo(serial: "D2760001240103040005000012340000", transport: .nfc, keys: [])
            }
            if CommandLine.arguments.contains("--ui-confirm") {
                model.prompts[0].kind = .confirm
                model.prompts[0].description = "Please insert the card with serial number: 0005 00001234"
            }
            if CommandLine.arguments.contains("--ui-ordinary-confirm") {
                model.prompts[0].kind = .confirm
                model.prompts[0].description = "Allow this operation?"
            }
            if CommandLine.arguments.contains("--ui-message") { model.prompts[0].kind = .message }
            if CommandLine.arguments.contains("--ui-operation-notification") {
                let core = InvitationFixtureClient(noHandle: .init())
                core.fixtureTokens = ["ui-pin", "ui-selected-pin"]
                model.client = core
                var selected = model.prompts[0]
                selected.token = "ui-selected-pin"
                selected.title = "Selected Notification Request"
                model.prompts.append(selected)
                model.receiveNotification(.operation(CommandLine.arguments.contains("--ui-expired-notification") ? "expired" : selected.token))
            }
            return model
        }
        if CommandLine.arguments.contains("--ui-members-fixture") {
            let model = AppModel(defaults: UserDefaults(suiteName: "hibiki-ui-members-fixture")!, nfcCapability: { CommandLine.arguments.contains("--ui-nfc") })
            let isOnline = CommandLine.arguments.contains("--ui-members-online")
            if CommandLine.arguments.contains("--ui-cards-fixture") {
                model.recordedNFCCard = CardInfo(serial: "D2760001240103040005000012340000", transport: .nfc, keys: [])

            }
            let words = (1...24).map { String(format: "word%02d", $0) }.joined(separator: " ")
            let local = DeviceInfo(id: String(repeating: "a", count: 64), name: "Fixture iPhone", words: words, online: isOnline, approvedBy: nil, approverName: nil, canRevoke: false, revokedByServer: false, reverseRevokeAvailableAt: nil, revocationSubtree: [])
            let remote = DeviceInfo(id: String(repeating: "b", count: 64), name: "Work Mac", words: words, online: isOnline, approvedBy: String(repeating: "d", count: 64), approverName: "Approving Mac", canRevoke: false, revokedByServer: false, reverseRevokeAvailableAt: nil, revocationSubtree: [])
            let child = DeviceInfo(id: String(repeating: "e", count: 64), name: "Approved laptop", words: words, online: isOnline, approvedBy: local.id, approverName: local.name, canRevoke: true, revokedByServer: false, reverseRevokeAvailableAt: nil, revocationSubtree: [String(repeating: "e", count: 64), String(repeating: "f", count: 64)])
            let grandchild = DeviceInfo(id: String(repeating: "f", count: 64), name: "Approved tablet", words: words, online: isOnline, approvedBy: child.id, approverName: child.name, canRevoke: true, revokedByServer: false, reverseRevokeAvailableAt: nil, revocationSubtree: [String(repeating: "f", count: 64)])
            if CommandLine.arguments.contains("--ui-members-online") { model.connection = "online" }
            model.device = local
            model.channels = [ChannelInfo(id: String(repeating: "c", count: 64), name: "UI Test Channel", active: true, revision: 1, members: [local, remote, child, grandchild])]
            if CommandLine.arguments.contains("--ui-pending-fixture") {
                model.channels[0].active = false
                model.pairing = JoinInfo(verification: "hibiki-verify-v1:pending-fixture", channel: model.channels[0].id, request: "pending-request-id")
            }
            if CommandLine.arguments.contains("--ui-invitations-fixture") {
                let client = InvitationFixtureClient(noHandle: .init())
                client.fixtureChannels = model.channels
                if CommandLine.arguments.contains("--ui-join-notification") {
                    client.fixturePending = [PendingInfo(id: "notification-request-id", channel: model.channels[0].id, device: remote)]
                    if CommandLine.arguments.contains("--ui-expired-notification") { client.fixturePending = [] }
                    model.receiveNotification(.join(channel: model.channels[0].id, request: "notification-request-id"))
                }
                client.creationAllowed = !CommandLine.arguments.contains("--ui-creation-denied")
                client.approveOnRefresh = CommandLine.arguments.contains("--ui-approve-pending")
                model.client = client
                model.allowChannelCreation = client.creationAllowed
            }
            model.initialized = true
            return model
        }
        #endif
        return AppModel()
    }
}

#if DEBUG
/// In-memory relay responses for exercising the real creation and invitation views.
private final class InvitationFixtureClient: MobileClient, @unchecked Sendable {
    private let lock = NSLock()
    var creationAllowed = true
    var approveOnRefresh = false
    var fixtureChannels: [ChannelInfo] = []
    var fixturePending: [PendingInfo] = []
    var fixtureTokens: Set<String> = []
    override func requestIsPending(token: String) -> Bool { fixtureTokens.contains(token) }
    private var refreshCount = 0
    private var withdrawn = false
    override func allowsChannelCreation() async throws -> Bool { creationAllowed }
    override func channels() async throws -> [ChannelInfo] {
        lock.withLock {
            refreshCount += 1
            if approveOnRefresh, refreshCount >= 2 { fixtureChannels[0].active = true }
            return fixtureChannels
        }
    }
    override func pairingStatus(channel: String, requestId: String) async throws -> PairingState {
        lock.withLock {
            if withdrawn { return .absent }
            return fixtureChannels.first(where: { $0.id == channel })?.active == true ? .member : .pending
        }
    }
    override func withdrawJoin(channel: String, requestId: String) async throws {
        lock.withLock { withdrawn = true }
    }
    override func pending(channel: String) async throws -> [PendingInfo] { fixturePending.filter { $0.channel == channel } }
    override func nfcCard() -> CardInfo? { nil }
    override func createChannel(name: String) async throws -> Invitation {
        guard creationAllowed else { throw MobileError.Failed(message: "Channel creation disabled") }
        let channel = ChannelInfo(id: "created-channel", name: name, active: true, revision: 1, members: [])
        lock.withLock { fixtureChannels.append(channel) }
        return try await invitation(channel: channel.id)
    }
    override func invitation(channel: String) async throws -> Invitation {
        Invitation(channel: channel, invite: "hibiki-invite-v2:ui-test-invitation", expiresAt: UInt64(Date().timeIntervalSince1970) + 86400)
    }
}
#endif
