import Foundation
import UserNotifications
import UIKit

// Only opaque routing IDs cross into notification metadata; never request contents.
enum RequestNoticeTarget: Hashable, Codable, Sendable {
    case operation(String)
    case join(channel: String, request: String)

    var identifier: String {
        switch self {
        case .operation(let token): return "operation:\(token)"
        case .join(let channel, let request): return "join:\(channel):\(request)"
        }
    }
    var isOperation: Bool { if case .operation = self { return true }; return false }
}

enum RequestNoticeKind: Sendable {
    case password, confirmation, message, card, join
    var body: String {
        switch self {
        case .password: return String(localized: "A password request needs your attention. Open Hibiki to continue.")
        case .confirmation: return String(localized: "An operation needs your confirmation. Open Hibiki to continue.")
        case .message: return String(localized: "An operation has a message for you. Open Hibiki to continue.")
        case .card: return String(localized: "A security key operation needs your attention. Open Hibiki to continue.")
        case .join: return String(localized: "A device is requesting to join a channel. Open Hibiki to review.")
        }
    }
    init(_ prompt: PinPrompt) {
        switch prompt.kind {
        case .pin: self = .password
        case .confirm: self = .confirmation
        case .message: self = .message
        case .cardUsb, .cardNfc: self = .card
        }
    }
}

enum NoticeAuthorization {
    case notDetermined, allowed, denied
    var label: String {
        switch self {
        case .notDetermined: return String(localized: "Not Requested")
        case .allowed: return String(localized: "Allowed")
        case .denied: return String(localized: "Not Allowed")
        }
    }
}

@MainActor
protocol RequestNotifications: AnyObject {
    var onOpen: (@MainActor (RequestNoticeTarget) -> Void)? { get set }
    func authorization(requestIfNeeded: Bool) async -> NoticeAuthorization
    func send(_ target: RequestNoticeTarget, kind: RequestNoticeKind)
    func remove(_ target: RequestNoticeTarget)
    func clearOperations()
    func clearAll()
}

@MainActor
final class SystemRequestNotifications: NSObject, RequestNotifications, UNUserNotificationCenterDelegate {
    var onOpen: (@MainActor (RequestNoticeTarget) -> Void)?
    private let center: UNUserNotificationCenter
    private var deliveries: [RequestNoticeTarget: UUID] = [:]
    private var permissionTask: Task<NoticeAuthorization, Never>?

    init(center: UNUserNotificationCenter = .current()) {
        self.center = center
        super.init()
        center.delegate = self
    }

    func authorization(requestIfNeeded: Bool) async -> NoticeAuthorization {
        let status = await center.notificationSettings().authorizationStatus
        guard status == .notDetermined, requestIfNeeded,
              UIApplication.shared.applicationState == .active else { return Self.permission(status) }
        if let permissionTask { return await permissionTask.value }
        let task = Task { @MainActor in
            _ = try? await center.requestAuthorization(options: [.alert, .sound])
            return Self.permission(await center.notificationSettings().authorizationStatus)
        }
        permissionTask = task
        let result = await task.value
        permissionTask = nil
        return result
    }
    private static func permission(_ status: UNAuthorizationStatus) -> NoticeAuthorization {
        switch status {
        case .authorized, .provisional, .ephemeral: return .allowed
        case .notDetermined: return .notDetermined
        default: return .denied
        }
    }

    nonisolated static func content(for target: RequestNoticeTarget, kind: RequestNoticeKind) -> UNMutableNotificationContent {
        let content = UNMutableNotificationContent()
        content.title = "Hibiki"
        content.body = kind.body
        content.sound = .default
        if let data = try? JSONEncoder().encode(target) { content.userInfo = ["route": data] }
        return content
    }

    func send(_ target: RequestNoticeTarget, kind: RequestNoticeKind) {
        guard deliveries[target] == nil else { return }
        let delivery = UUID()
        deliveries[target] = delivery
        Task {
            guard deliveries[target] == delivery else { return }
            do {
                try await center.add(UNNotificationRequest(identifier: target.identifier, content: Self.content(for: target, kind: kind), trigger: nil))
            } catch {
                if deliveries[target] == delivery { deliveries[target] = nil }
            }
            // Removal can race an asynchronous add. Clean up again after it completes.
            if deliveries[target] == nil { removeFromCenter([target.identifier]) }
        }
    }
    func remove(_ target: RequestNoticeTarget) {
        deliveries[target] = nil
        removeFromCenter([target.identifier])
    }
    func clearOperations() {
        let targets = deliveries.keys.filter(\.isOperation)
        for target in targets { remove(target) }
    }
    func clearAll() {
        deliveries.removeAll()
        center.removeAllPendingNotificationRequests()
        center.removeAllDeliveredNotifications()
    }
    private func removeFromCenter(_ identifiers: [String]) {
        center.removePendingNotificationRequests(withIdentifiers: identifiers)
        center.removeDeliveredNotifications(withIdentifiers: identifiers)
    }
    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification, withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([])
    }
    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse, withCompletionHandler completionHandler: @escaping () -> Void) {
        if response.actionIdentifier == UNNotificationDefaultActionIdentifier,
           let data = response.notification.request.content.userInfo["route"] as? Data,
           let target = try? JSONDecoder().decode(RequestNoticeTarget.self, from: data) {
            Task { @MainActor [weak self] in self?.onOpen?(target) }
        }
        completionHandler()
    }
}
