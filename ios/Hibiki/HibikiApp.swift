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
                    if CommandLine.arguments.contains("--ui-members-fixture") { return }
                    #endif
                    await model.restore()
                }
                .onChange(of: scenePhase) { _, phase in model.sceneChanged(phase) }
        }
    }
    @MainActor private static func initialModel() -> AppModel {
        #if DEBUG
        // UI-only fixture: no client, saved identity, network or service execution.
        if CommandLine.arguments.contains("--ui-members-fixture") {
            let model = AppModel(defaults: UserDefaults(suiteName: "hibiki-ui-members-fixture")!)
            let words = (1...24).map { String(format: "word%02d", $0) }.joined(separator: " ")
            let local = DeviceInfo(id: String(repeating: "a", count: 64), name: "Fixture iPhone", words: words, online: false, approvedBy: nil, approverName: nil, canRevoke: false, revokedByServer: false, reverseRevokeAvailableAt: nil, revocationSubtree: [])
            let remote = DeviceInfo(id: String(repeating: "b", count: 64), name: "Work Mac", words: words, online: false, approvedBy: String(repeating: "d", count: 64), approverName: "Approving Mac", canRevoke: false, revokedByServer: false, reverseRevokeAvailableAt: nil, revocationSubtree: [])
            let child = DeviceInfo(id: String(repeating: "e", count: 64), name: "Approved laptop", words: words, online: false, approvedBy: local.id, approverName: local.name, canRevoke: true, revokedByServer: false, reverseRevokeAvailableAt: nil, revocationSubtree: [String(repeating: "e", count: 64), String(repeating: "f", count: 64)])
            let grandchild = DeviceInfo(id: String(repeating: "f", count: 64), name: "Approved tablet", words: words, online: false, approvedBy: child.id, approverName: child.name, canRevoke: true, revokedByServer: false, reverseRevokeAvailableAt: nil, revocationSubtree: [String(repeating: "f", count: 64)])
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
