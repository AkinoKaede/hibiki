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
                    if CommandLine.arguments.contains("--ui-members-fixture") || CommandLine.arguments.contains("--ui-pin-fixture") { return }
                    #endif
                    await model.restore()
                }
                .onChange(of: scenePhase) { _, phase in model.sceneChanged(phase) }
        }
    }
    @MainActor private static func initialModel() -> AppModel {
        #if DEBUG
        // UI-only fixture: no client, saved identity, network or service execution.
        if CommandLine.arguments.contains("--ui-pin-fixture") {
            let model = AppModel(defaults: UserDefaults(suiteName: "hibiki-ui-pin-fixture")!, nfcCapability: { CommandLine.arguments.contains("--ui-nfc") })
            model.initialized = true
            model.prompts = [PinPrompt(token: "ui-pin", session: "ui-session", request: 1, channel: "UI Test Channel", deviceName: "Work Mac", deviceId: String(repeating: "b", count: 64), kind: .pin, title: "Hibiki Request", description: "Please enter the PIN for your security key.", label: "PIN", error: "", repeat: "", repeatError: "", ok: "OK", cancel: "", notOk: "", timeoutSeconds: 120)]
            if CommandLine.arguments.contains("--ui-nfc") {
                model.registeredCards = [RegisteredCard(card: CardInfo(serial: "D2760001240103040005000012340000", transport: .nfc, keys: []), name: "Fixture Security Key", usbEnabled: true, nfcEnabled: true)]
            }
            if CommandLine.arguments.contains("--ui-confirm") {
                model.prompts[0].kind = .confirm
                model.prompts[0].description = "Please insert the card with serial number: 0005 00001234"
            }
            return model
        }
        if CommandLine.arguments.contains("--ui-members-fixture") {
            let model = AppModel(defaults: UserDefaults(suiteName: "hibiki-ui-members-fixture")!, nfcCapability: { CommandLine.arguments.contains("--ui-nfc") })
            let isOnline = CommandLine.arguments.contains("--ui-members-online")
            if CommandLine.arguments.contains("--ui-cards-fixture") {
                model.registeredCards = [RegisteredCard(card: CardInfo(serial: "D2760001240103040005000012340000", transport: .usb, keys: []), name: "Fixture Security Key", usbEnabled: true, nfcEnabled: true)]
                if CommandLine.arguments.contains("--ui-multiple-nfc") {
                    model.registeredCards.append(RegisteredCard(card: CardInfo(serial: "D2760001240100000006120808620000", transport: .nfc, keys: []), name: "Second Security Key", usbEnabled: true, nfcEnabled: true))
                }
            }
            let words = (1...24).map { String(format: "word%02d", $0) }.joined(separator: " ")
            let local = DeviceInfo(id: String(repeating: "a", count: 64), name: "Fixture iPhone", words: words, online: isOnline, approvedBy: nil, approverName: nil, canRevoke: false, revokedByServer: false, reverseRevokeAvailableAt: nil, revocationSubtree: [])
            let remote = DeviceInfo(id: String(repeating: "b", count: 64), name: "Work Mac", words: words, online: isOnline, approvedBy: String(repeating: "d", count: 64), approverName: "Approving Mac", canRevoke: false, revokedByServer: false, reverseRevokeAvailableAt: nil, revocationSubtree: [])
            let child = DeviceInfo(id: String(repeating: "e", count: 64), name: "Approved laptop", words: words, online: isOnline, approvedBy: local.id, approverName: local.name, canRevoke: true, revokedByServer: false, reverseRevokeAvailableAt: nil, revocationSubtree: [String(repeating: "e", count: 64), String(repeating: "f", count: 64)])
            let grandchild = DeviceInfo(id: String(repeating: "f", count: 64), name: "Approved tablet", words: words, online: isOnline, approvedBy: child.id, approverName: child.name, canRevoke: true, revokedByServer: false, reverseRevokeAvailableAt: nil, revocationSubtree: [String(repeating: "f", count: 64)])
            if CommandLine.arguments.contains("--ui-members-online") { model.connection = "online" }
            model.device = local
            model.channels = [ChannelInfo(id: String(repeating: "c", count: 64), name: "UI Test Channel", active: true, revision: 1, members: [local, remote, child, grandchild])]
            model.initialized = true
            return model
        }
        #endif
        return AppModel()
    }
}
