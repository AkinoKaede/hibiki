import SwiftUI

@main
struct HibikiApp: App {
    @State private var model = AppModel()
    @Environment(\.scenePhase) private var scenePhase
    var body: some Scene {
        WindowGroup {
            RootView(model: model)
                .task { await model.restore() }
                .onChange(of: scenePhase) { _, phase in model.sceneChanged(phase) }
        }
    }
}
