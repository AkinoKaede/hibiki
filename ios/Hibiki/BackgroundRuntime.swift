/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Kaede Akino
 */

import UIKit

/// UIKit calls expiration handlers on the main thread. Keep cancellation synchronous.
@MainActor
protocol BackgroundRuntime: AnyObject {
    func begin(expiration: @escaping @MainActor () -> Void) -> Int?
    func end(_ identifier: Int)
}

@MainActor
final class SystemBackgroundRuntime: BackgroundRuntime {
    func begin(expiration: @escaping @MainActor () -> Void) -> Int? {
        let identifier = UIApplication.shared.beginBackgroundTask(withName: "Hibiki requests") {
            MainActor.assumeIsolated { expiration() }
        }
        return identifier == .invalid ? nil : identifier.rawValue
    }
    func end(_ identifier: Int) {
        UIApplication.shared.endBackgroundTask(UIBackgroundTaskIdentifier(rawValue: identifier))
    }
}
