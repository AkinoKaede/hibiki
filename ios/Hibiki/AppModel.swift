import DeviceKit
import SwiftUI
import Observation

enum ChannelRoute: Hashable {
    case channel(String)
    case approval(channel: String, request: String)
}

@MainActor @Observable
final class AppModel {
    var client: MobileClient?
    var device: DeviceInfo?
    var channels: [ChannelInfo] = []
    private(set) var nfcAvailable: Bool
    @ObservationIgnored private let readNFCCapability: () -> Bool
    var recordedNFCCard: CardInfo?
    @ObservationIgnored private var nfcReadCancellation: CardReadCancellation?
    var connection = "offline"
    var error: String?
    var unavailableNotification: RequestNoticeTarget?
    var busy = false
    var prompts: [PinPrompt] = []
    var usbPresent = false
    let cardInspection = CardInspection()
    var foreground = true
    var server: String
    var name: String
    var skipTLSCertificateValidation: Bool
    var pinEnabled: Bool
    var cardEnabled: Bool
    var initialized = false
    var pairing: JoinInfo?
    var allowChannelCreation: Bool?
    private let hardware: any CardHardwareAccess
    private var eventTask: Task<Void, Never>?
    private var pollingTask: Task<Void, Never>?
    private var usbTask: Task<Void, Never>?
    private var lastUSBState: USBState?
    private var nativeTasks: [String: Task<Void, Never>] = [:]
    private var lifecycleTask: Task<Void, Never>?
    private var disconnecting = false
    @ObservationIgnored private let backgroundRuntime: BackgroundRuntime
    @ObservationIgnored private let notifications: RequestNotifications
    private var backgroundIdentifier: Int?
    private var lifecycleGeneration = 0
    private var backgroundExpired = false
    private var hardwareReady = true
    private var deferredCardOpens: [String: NativeEvent] = [:]
    private var notifiedOperations: Set<String> = []
    private var seenJoins: [String: Set<String>] = [:]
    private var requestRefreshGeneration = 0
    private var pendingNotification: RequestNoticeTarget?
    private var notificationRouteGeneration = 0
    private(set) var notificationAuthorization: NoticeAuthorization = .notDetermined
    private(set) var pendingJoins: [String: [PendingInfo]] = [:]
    var selectedTab = "status"
    var channelPath: [ChannelRoute] = []

    private let defaults: UserDefaults
    private let resetRelayStorage: () throws -> Void

    init(defaults: UserDefaults = .standard, resetRelayStorage: @escaping () throws -> Void = SecureStorage.resetRelay, nfcCapability: @escaping () -> Bool = { CardHardware.nfcReadingAvailable }, backgroundRuntime: BackgroundRuntime? = nil, notifications: RequestNotifications? = nil, hardware: any CardHardwareAccess = CardHardware()) {
        self.hardware = hardware
        self.backgroundRuntime = backgroundRuntime ?? SystemBackgroundRuntime()
        self.notifications = notifications ?? SystemRequestNotifications()
        self.readNFCCapability = nfcCapability
        self.nfcAvailable = nfcCapability()
        self.defaults = defaults
        self.resetRelayStorage = resetRelayStorage
        server = defaults.string(forKey: "server") ?? ""
        name = defaults.string(forKey: "deviceName") ?? Device.current.realDevice.description
        skipTLSCertificateValidation = defaults.bool(forKey: "skipTLSCertificateValidation")
        pinEnabled = defaults.object(forKey: "pinEnabled") as? Bool ?? true
        cardEnabled = defaults.object(forKey: "cardEnabled") as? Bool ?? true
        if let channel = defaults.string(forKey: "pairingChannel"), let request = defaults.string(forKey: "pairingRequest") {
            pairing = JoinInfo(verification: defaults.string(forKey: "pairingVerification") ?? "", channel: channel, request: request)
        }
        self.notifications.onOpen = { [weak self] target in self?.receiveNotification(target) }
    }

    nonisolated static func serverURLs(from input: String) throws -> [String] {
        let value = input.trimmingCharacters(in: .whitespacesAndNewlines)
        let explicitScheme = value.contains("://")
        let address = explicitScheme ? value : "wss://" + value
        guard !value.isEmpty, !value.contains(where: { $0.isWhitespace }),
              var url = URLComponents(string: address),
              let scheme = url.scheme?.lowercased(), ["ws", "wss"].contains(scheme),
              let host = url.host, !host.isEmpty,
              url.user == nil, url.password == nil, url.fragment == nil,
              url.port.map({ (1...65535).contains($0) }) ?? true else {
            throw NSError(domain: "Hibiki.ServerAddress", code: 1, userInfo: [NSLocalizedDescriptionKey: String(localized: "Enter a valid server address, with or without wss:// or ws://.")])
        }
        url.scheme = scheme
        if url.path.isEmpty || url.path == "/" { url.path = "/hibiki" }
        guard let result = url.url?.absoluteString else {
            throw NSError(domain: "Hibiki.ServerAddress", code: 1, userInfo: [NSLocalizedDescriptionKey: String(localized: "Enter a valid server address, with or without wss:// or ws://.")])
        }
        if explicitScheme { return [result] }
        url.scheme = "ws"
        return [result, url.url!.absoluteString]
    }

    static func discoverServer(from input: String, probe: (String) async throws -> Void) async throws -> String {
        let candidates = try serverURLs(from: input)
        var failures: [String] = []
        for candidate in candidates {
            try Task.checkCancellation()
            do {
                // Each probe checks the Hibiki protocol and authentication, not just the port.
                try await probe(candidate)
                try Task.checkCancellation()
                return candidate
            } catch is CancellationError {
                throw CancellationError()
            } catch {
                try Task.checkCancellation()
                failures.append("\(candidate): \(error.localizedDescription)")
            }
        }
        throw NSError(domain: "Hibiki.ServerConnection", code: 1, userInfo: [NSLocalizedDescriptionKey: failures.joined(separator: "\n\n")])
    }

    var currentPrompt: PinPrompt? {
        guard foreground, unavailableNotification == nil, selectedTab != "channels" || channelPath.isEmpty else { return nil }
        return prompts.first
    }
    func refreshHardwareCapabilities() {
        nfcAvailable = readNFCCapability()
        cardInspection.setNFCAvailable(nfcAvailable)
        client?.setNfcAvailable(available: nfcAvailable)
        if !nfcAvailable { recordedNFCCard = nil }
    }
    var statusText: String {
        switch connection {
        case "online": return String(localized: "Online")
        case "connecting": return String(localized: "Connecting")
        default: return String(localized: "Offline")
        }
    }
    func restore() async {
        if defaults.bool(forKey: "relayResetPending") {
            await disconnectRelay()
            return
        }
        guard defaults.string(forKey: "server") != nil, !server.isEmpty else { return }
        do {
            if let identity = try SecureStorage.identity() {
                try configure(identity: identity)
                await activate()
            }
        } catch { show(error) }
    }
    func setup() async {
        guard !busy else { return }
        await perform {
            if self.defaults.bool(forKey: "relayResetPending") {
                try self.resetRelayStorage()
                self.defaults.removeObject(forKey: "relayResetPending")
            }
            guard !self.server.isEmpty, !self.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return }
            let input = self.server
            let name = self.name.trimmingCharacters(in: .whitespacesAndNewlines)
            let skipTLS = self.skipTLSCertificateValidation
            // A previous interrupted setup may already have saved an identity; never replace it.
            let savedIdentity = try SecureStorage.identity()
            let identity = try savedIdentity ?? createIdentity(name: name)
            let server: String
            do {
                server = try await Self.discoverServer(from: input) { candidate in
                    guard self.foreground else { throw CancellationError() }
                    try await checkRelay(server: candidate, identity: identity, skipTlsCertificateValidation: skipTLS)
                }
            } catch is CancellationError {
                return
            } catch {
                self.show(error)
                self.error = String(localized: "Could not connect to the server. Check the address and try again.") + "\n\n" + (self.error ?? "")
                return
            }
            guard self.foreground, !Task.isCancelled else { return }
            if savedIdentity == nil { try SecureStorage.saveIdentity(identity) }
            self.server = server
            self.name = name
            try self.configure(identity: identity)
            self.defaults.set(self.server, forKey: "server")
            self.defaults.set(self.name, forKey: "deviceName")
            self.defaults.set(self.skipTLSCertificateValidation, forKey: "skipTLSCertificateValidation")
            await self.activate()
        }
    }
    func renameDevice(_ newName: String) async {
        guard !busy else { return }
        await perform {
            guard let core = self.client else { return }
            let identity = try await core.renameDevice(name: newName)
            try SecureStorage.updateIdentity(identity)
            await core.stop()
            self.eventTask?.cancel()
            try self.configure(identity: identity)
            self.name = newName
            self.defaults.set(newName, forKey: "deviceName")
            await self.activate()
            await self.refresh()
        }
    }
    func disconnectRelay() async {
        guard !busy else { return }
        busy = true
        disconnecting = true
        defer { busy = false; disconnecting = false }
        // Persist intent first so an interrupted reset cannot restore the old connection.
        defaults.set(true, forKey: "relayResetPending")
        for key in ["server", "skipTLSCertificateValidation", "pinEnabled", "cardEnabled"] {
            defaults.removeObject(forKey: key)
        }
        let core = client
        lifecycleGeneration += 1
        endBackgroundRuntime()
        core?.requestStop()
        notifications.clearAll()
        notifiedOperations.removeAll()
        pendingNotification = nil
        unavailableNotification = nil
        notificationRouteGeneration += 1
        pendingJoins.removeAll()
        seenJoins.removeAll()
        channelPath.removeAll()
        requestRefreshGeneration += 1
        usbTask?.cancel(); usbTask = nil
        lastUSBState = nil
        client = nil
        core?.setServices(pinentry: false, card: false)
        eventTask?.cancel(); eventTask = nil
        await lifecycleTask?.value
        await deactivate()
        await core?.stop()
        device = nil
        channels = []
        rememberPairing(nil)
        allowChannelCreation = nil
        recordedNFCCard = nil
        usbPresent = false
        cardInspection.reset()
        pinEnabled = true
        cardEnabled = true
        skipTLSCertificateValidation = false
        connection = "offline"
        server = ""
        initialized = false
        error = nil
        do {
            try self.resetRelayStorage()
            defaults.removeObject(forKey: "relayResetPending")
        } catch { show(error) }
    }
    private func configure(identity: Data) throws {
        let core = try MobileClient(directory: SecureStorage.directory().path, server: server, identity: identity, skipTlsCertificateValidation: skipTLSCertificateValidation)
        lifecycleGeneration += 1
        endBackgroundRuntime()
        notifications.clearAll()
        notifiedOperations.removeAll()
        deferredCardOpens.removeAll()
        prompts.removeAll()
        pendingJoins.removeAll()
        seenJoins.removeAll()
        requestRefreshGeneration += 1
        usbTask?.cancel(); usbTask = nil
        lastUSBState = nil
        client = core
        device = try core.device()
        refreshHardwareCapabilities()
        recordedNFCCard = core.nfcCard()
        initialized = true
        core.setServices(pinentry: pinEnabled, card: cardEnabled)
        eventTask?.cancel()
        eventTask = Task { [weak self] in
            while !Task.isCancelled, let event = await core.nextEvent() {
                guard let self else { return }
                guard !Task.isCancelled, self.client === core else { return }
                self.handle(event, core: core)
            }
        }
    }
    #if DEBUG
    /// Physical-device UI test: a real public NFC read plus a synthetic queued
    /// confirmation. No relay, saved account, PIN or custom presentation policy.
    func configureNFCOrderFixture() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("nfc-order-\(UUID().uuidString)")
        let core = try MobileClient(directory: directory.path, server: "ws://127.0.0.1:1/hibiki", identity: createIdentity(name: "NFC UI Test"), skipTlsCertificateValidation: false)
        usbTask?.cancel(); usbTask = nil
        lastUSBState = nil
        client = core
        device = try core.device()
        initialized = true
        refreshHardwareCapabilities()
        eventTask = Task { [weak self] in
            var queued = false
            while !Task.isCancelled, let event = await core.nextEvent() {
                guard let self, self.client === core else { return }
                self.handle(event, core: core)
                if case .cardOpen(_, _, .nfc) = event, !queued {
                    queued = true
                    Task { [weak self] in
                        try? await Task.sleep(for: .seconds(1))
                        self?.prompts.append(PinPrompt(token: "nfc-order-confirm", session: "ui-test", request: 1, channel: "UI Test", deviceName: "Test Requester", deviceId: "ui-test", kind: .confirm, title: "NFC Presentation Test", description: "NFC order test confirmation", label: "", error: "", repeat: "", repeatError: "", ok: "Continue", cancel: "Cancel", notOk: "", timeoutSeconds: 120))
                    }
                }
            }
        }
    }
    #endif

    func sceneChanged(_ phase: ScenePhase) {
        // NFC and permission sheets can make the scene inactive without backgrounding it.
        guard phase != .inactive else { return }
        let wasForeground = foreground
        foreground = phase == .active
        guard wasForeground != foreground, !disconnecting else { return }
        lifecycleGeneration += 1
        let generation = lifecycleGeneration
        if foreground {
            endBackgroundRuntime()
            refreshHardwareCapabilities()
            notifications.clearOperations()
        } else {
            backgroundExpired = false
            pauseHardware()
            if let core = client {
                backgroundIdentifier = backgroundRuntime.begin { [weak self, weak core] in
                    guard let self, let core else { return }
                    self.expireBackground(generation: generation, core: core)
                }
                if backgroundExpired { endBackgroundRuntime() }
                else if backgroundIdentifier == nil { expireBackground(generation: generation, core: core) }
                if !backgroundExpired {
                    for prompt in prompts where core.requestIsPending(token: prompt.token) {
                        notifyOperation(prompt.token, kind: RequestNoticeKind(prompt))
                    }
                    for token in deferredCardOpens.keys where core.requestIsPending(token: token) {
                        notifyOperation(token, kind: .card)
                    }
                }
            }
        }
        let previous = lifecycleTask
        lifecycleTask = Task {
            await previous?.value
            // Always finish releasing old readers before a later activation can open one.
            if phase == .background { await hardware.closeAll() }
            guard generation == lifecycleGeneration, !disconnecting else { return }
            if foreground { await activateConnection() }
            else if !backgroundExpired { startPolling() }
        }
    }

    private func endBackgroundRuntime() {
        if let identifier = backgroundIdentifier {
            backgroundIdentifier = nil
            backgroundRuntime.end(identifier)
        }
    }

    private func expireBackground(generation: Int, core: MobileClient) {
        guard generation == lifecycleGeneration, !foreground, client === core, !backgroundExpired else { return }
        backgroundExpired = true
        // No await here: iOS may suspend us as soon as this handler returns.
        core.requestStop()
        pollingTask?.cancel(); pollingTask = nil
        requestRefreshGeneration += 1
        pauseHardware()
        prompts.removeAll()
        deferredCardOpens.removeAll()
        notifiedOperations.removeAll()
        notifications.clearOperations()
        connection = "offline"
        allowChannelCreation = nil
        endBackgroundRuntime()
        let previous = lifecycleTask
        lifecycleTask = Task {
            await previous?.value
            await hardware.closeAll()
            await core.stop()
        }
    }

    private func pauseHardware() {
        hardwareReady = false
        cardInspection.setActive(false)
        nfcReadCancellation?.cancel()
        for (token, task) in nativeTasks {
            try? client?.failNativeRequest(token: token, message: "App entered background", canceled: true)
            task.cancel()
        }
        nativeTasks.removeAll()
    }

    func activate() async {
        let previous = lifecycleTask
        let generation = lifecycleGeneration
        let activation = Task {
            await previous?.value
            guard generation == lifecycleGeneration else { return }
            await activateConnection()
        }
        lifecycleTask = activation
        await activation.value
    }

    private func activateConnection() async {
        guard foreground, !disconnecting, let core = client else { return }
        backgroundExpired = false
        do { try await core.start() } catch { show(error) }
        guard foreground, !disconnecting, client === core else {
            if backgroundExpired || disconnecting || client !== core { core.requestStop() }
            return
        }
        await syncUSBState()
        guard foreground, client === core, !disconnecting else { return }
        if usbTask == nil {
            let events = await hardware.usbEvents()
            usbTask = Task { [weak self] in
                for await state in events {
                    guard !Task.isCancelled, let self, self.client === core else { return }
                    self.applyUSBState(state, core: core)
                }
            }
        }
        hardwareReady = true
        cardInspection.setActive(true)
        prompts.removeAll { !core.requestIsPending(token: $0.token) }
        notifiedOperations = notifiedOperations.filter { core.requestIsPending(token: $0) }
        notifications.clearOperations()
        await openPendingNotification()
        guard foreground, client === core else { return }
        let deferred = deferredCardOpens
        deferredCardOpens.removeAll()
        for (token, event) in deferred where core.requestIsPending(token: token) { handle(event, core: core) }
        startPolling()
        Task { await refreshNotificationAuthorization() }
    }

    private func startPolling() {
        pollingTask?.cancel()
        guard let core = client else { return }
        pollingTask = Task {
            while !Task.isCancelled, client === core, foreground || !backgroundExpired {
                if foreground {
                    await refresh()
                } else {
                    await refreshPendingRequests()
                }
                try? await Task.sleep(for: .seconds(3))
            }
        }
    }

    /// One-shot state reconciliation, never reads card information or sends APDUs.
    func syncUSBState() async {
        guard foreground, let core = client else { return }
        let state = await hardware.usbState()
        guard foreground, client === core, !Task.isCancelled else { return }
        applyUSBState(state, core: core)
    }

    private func applyUSBState(_ state: USBState, core: MobileClient) {
        guard lastUSBState == nil || state.revision > lastUSBState!.revision else { return }
        if let old = lastUSBState,
           !Set(old.connections).subtracting(state.connections).isEmpty {
            cardInspection.usbRemoved()
        }
        lastUSBState = state
        usbPresent = !state.connections.isEmpty
        core.usbConnections(connections: state.connections)
        cardInspection.usbChanged(usbPresent)
    }
    func deactivate() async {
        endBackgroundRuntime()
        pollingTask?.cancel(); pollingTask = nil
        requestRefreshGeneration += 1
        pauseHardware()
        prompts.removeAll()
        deferredCardOpens.removeAll()
        notifiedOperations.removeAll()
        notifications.clearOperations()
        await hardware.closeAll()
        await client?.stop()
        connection = "offline"
        allowChannelCreation = nil
    }

    func refreshNotificationAuthorization() async {
        guard foreground else { return }
        notificationAuthorization = await notifications.authorization(requestIfNeeded: initialized && connection == "online")
    }

    private func notifyOperation(_ token: String, kind: RequestNoticeKind) {
        guard !foreground, !backgroundExpired, notifiedOperations.insert(token).inserted else { return }
        notifications.send(.operation(token), kind: kind)
    }

    func refreshPendingRequests(channels snapshot: [ChannelInfo]? = nil) async {
        guard let core = client, connection == "online", foreground || !backgroundExpired else { return }
        requestRefreshGeneration += 1
        let generation = requestRefreshGeneration
        do {
            let channels: [ChannelInfo]
            if let snapshot { channels = snapshot }
            else { channels = try await core.channels() }
            guard canApplyRequests(core, generation: generation) else { return }
            let active = Set(channels.filter(\.active).map(\.id))
            for channel in Array(pendingJoins.keys) where !active.contains(channel) {
                for request in pendingJoins.removeValue(forKey: channel) ?? [] {
                    notifications.remove(.join(channel: channel, request: request.id))
                }
                seenJoins[channel] = nil
            }
            for channel in channels where channel.active {
                do {
                    let requests = try await core.pending(channel: channel.id)
                    guard canApplyRequests(core, generation: generation) else { return }
                    let ids = Set(requests.map(\.id))
                    let old = seenJoins[channel.id] ?? []
                    for removed in old.subtracting(ids) { notifications.remove(.join(channel: channel.id, request: removed)) }
                    if !foreground {
                        for request in requests where !old.contains(request.id) {
                            notifications.send(.join(channel: channel.id, request: request.id), kind: .join)
                        }
                    }
                    seenJoins[channel.id] = ids
                    pendingJoins[channel.id] = requests
                } catch { /* A failed query must not erase a successful snapshot. */ }
            }
        } catch { /* Retry transient relay failures on the next poll. */ }
    }

    private func canApplyRequests(_ core: MobileClient, generation: Int) -> Bool {
        client === core && !Task.isCancelled && generation == requestRefreshGeneration && connection == "online" && (foreground || !backgroundExpired)
    }

    func receiveNotification(_ target: RequestNoticeTarget) {
        unavailableNotification = nil
        notificationRouteGeneration += 1
        pendingNotification = target
        Task { await openPendingNotification() }
    }

    func openPendingNotification() async {
        guard foreground, let target = pendingNotification, let core = client else { return }
        if case .join(let channel, _) = target {
            selectedTab = "channels"
            channelPath = [.channel(channel)]
            if connection != "online" { return }
        }
        let routeGeneration = notificationRouteGeneration
        pendingNotification = nil
        notifications.remove(target)
        switch target {
        case .operation(let token):
            selectedTab = "status"
            guard core.requestIsPending(token: token) else {
                unavailableNotification = target
                return
            }
            if let index = prompts.firstIndex(where: { $0.token == token }) {
                let prompt = prompts.remove(at: index)
                prompts.insert(prompt, at: 0)
            }
        case .join(let channel, let request):
            selectedTab = "channels"
            channelPath = [.channel(channel)]
            do {
                let requests = try await core.pending(channel: channel)
                guard client === core, routeGeneration == notificationRouteGeneration else { return }
                guard foreground else { pendingNotification = target; return }
                requestRefreshGeneration += 1
                pendingJoins[channel] = requests
                if requests.contains(where: { $0.id == request }) {
                    channelPath.append(.approval(channel: channel, request: request))
                } else { unavailableNotification = target }
            } catch {
                guard client === core, routeGeneration == notificationRouteGeneration else { return }
                guard foreground else { pendingNotification = target; return }
                show(error)
            }
        }
    }
    func refresh() async {
        guard let client, foreground else { return }
        recordedNFCCard = client.nfcCard()
        do {
            let channels = try await client.channels()
            guard foreground, self.client === client, !Task.isCancelled else { return }
            self.channels = channels
            if connection == "online" {
                let allowed = try await client.allowsChannelCreation()
                guard foreground, self.client === client, !Task.isCancelled, connection == "online" else { return }
                allowChannelCreation = allowed
                if let pairing, !busy {
                    let state = try await client.pairingStatus(channel: pairing.channel, requestId: pairing.request)
                    guard foreground, self.client === client, !Task.isCancelled, !busy, self.pairing?.request == pairing.request else { return }
                    switch state {
                    case .member: rememberPairing(nil)
                    case .absent:
                        rememberPairing(nil)
                        error = String(localized: "This join request was rejected or has expired. Get a new invitation to try again.")
                    case .pending: break
                    }
                }
            }
            await refreshPendingRequests(channels: channels)
        } catch { /* The connection state communicates transient relay failures. */ }
    }
    func rememberPairing(_ value: JoinInfo?) {
        // Initialization invitations claim membership immediately and have no pending ID.
        pairing = value?.request.isEmpty == false ? value : nil
        defaults.set(pairing?.channel, forKey: "pairingChannel")
        defaults.set(pairing?.request, forKey: "pairingRequest")
        defaults.set(pairing?.verification, forKey: "pairingVerification")
    }
    func withdrawPairing() async {
        guard let pairing, let client else { return }
        await perform {
            try await client.withdrawJoin(channel: pairing.channel, requestId: pairing.request)
            if self.client === client, self.pairing?.request == pairing.request { self.rememberPairing(nil) }
            await self.refresh()
        }
    }
    func updateServices() {
        guard !disconnecting else { return }
        client?.setServices(pinentry: pinEnabled, card: cardEnabled)
        defaults.set(pinEnabled, forKey: "pinEnabled")
        defaults.set(cardEnabled, forKey: "cardEnabled")
    }
    func recordNFCCard() async {
        guard !busy, foreground, hardwareReady, let client else { return }
        busy = true
        let cancellation = CardReadCancellation()
        nfcReadCancellation = cancellation
        defer { busy = false; nfcReadCancellation = nil }
        do {
            _ = try await client.recordNfcCard(expectedNumber: nil, cancellation: cancellation)
            guard foreground, self.client === client else { return }
            recordedNFCCard = client.nfcCard()
        } catch {
            if case MobileError.Cancelled = error { return }
            show(error)
        }
    }
    func clearNFCRecord() {
        nfcReadCancellation?.cancel()
        client?.clearNfcCard()
        recordedNFCCard = nil
    }
    func continueCardInsertion(_ prompt: PinPrompt) async throws {
        guard !busy, foreground, hardwareReady, let client else { throw CancellationError() }
        busy = true
        let cancellation = CardReadCancellation()
        nfcReadCancellation = cancellation
        defer {
            busy = false
            nfcReadCancellation = nil
            if !client.requestIsPending(token: prompt.token) { prompts.removeAll { $0.token == prompt.token } }
        }
        await syncUSBState()
        guard foreground, self.client === client, client.requestIsPending(token: prompt.token) else { throw CancellationError() }
        try await client.continueCardInsertion(prompt: prompt, cancellation: cancellation)
        recordedNFCCard = client.nfcCard()
        prompts.removeAll { $0.token == prompt.token }
    }
    func showCardInspection() {
        refreshHardwareCapabilities()
        cardInspection.appear(usbPresent: usbPresent, active: foreground && hardwareReady) { [weak self] transport in
            guard let self, self.foreground, self.hardwareReady, let core = self.client else { throw CancellationError() }
            let cancellation = CardReadCancellation()
            return try await withTaskCancellationHandler {
                try Task.checkCancellation()
                return try await core.inspectCard(transport: transport, cancellation: cancellation)
            } onCancel: { cancellation.cancel() }
        }
    }
    func answer(_ prompt: PinPrompt, text: String = "", accepted: Bool) {
        guard foreground, let client else { return }
        defer {
            prompts.removeAll { $0.token == prompt.token }
            notifiedOperations.remove(prompt.token)
            notifications.remove(.operation(prompt.token))
        }
        do { try client.respond(token: prompt.token, data: Data(text.utf8), accepted: accepted) }
        catch { if client.requestIsPending(token: prompt.token) { show(error) } }
    }
    func cancelPrompt(_ prompt: PinPrompt) {
        guard foreground, let client else { return }
        defer {
            prompts.removeAll { $0.token == prompt.token }
            notifiedOperations.remove(prompt.token)
            notifications.remove(.operation(prompt.token))
        }
        do { try client.cancelRequest(token: prompt.token) }
        catch { if client.requestIsPending(token: prompt.token) { show(error) } }
    }
    func handle(_ event: NativeEvent, core: MobileClient) {
        guard client === core else { return }
        switch event {
        case .connection(let state):
            guard foreground || !backgroundExpired else { return }
            connection = state
            if state != "online" { allowChannelCreation = nil }
            else if foreground {
                Task {
                    await refreshNotificationAuthorization()
                    await openPendingNotification()
                }
            }
        case .prompt(let prompt):
            guard !backgroundExpired, core.requestIsPending(token: prompt.token), !prompts.contains(where: { $0.token == prompt.token }) else { return }
            prompts.append(prompt)
            notifyOperation(prompt.token, kind: RequestNoticeKind(prompt))
        case .cancelled(let token):
            prompts.removeAll { $0.token == token }
            deferredCardOpens[token] = nil
            notifiedOperations.remove(token)
            notifications.remove(.operation(token))
            nativeTasks.removeValue(forKey: token)?.cancel()
            Task { await hardware.cancel(token: token) }
        case .cardChanged: recordedNFCCard = core.nfcCard()
        case .cardClose(let id): Task { await hardware.close(id: id) }
        case .cardOpen(let token, let id, let transport):
            guard !backgroundExpired, core.requestIsPending(token: token) else { return }
            if !foreground || !hardwareReady {
                deferredCardOpens[token] = event
                notifyOperation(token, kind: .card)
                return
            }
            native(token: token, core: core) {
                let result = try await self.hardware.open(id: id, token: token, transport: transport)
                await self.syncUSBState()
                return result
            }
        case .cardTransmit(let token, let id, let command):
            guard foreground, hardwareReady else {
                try? core.failNativeRequest(token: token, message: "App entered background", canceled: true)
                return
            }
            native(token: token, core: core) { try await self.hardware.transmit(id: id, token: token, command: command) }
        }
    }
    private func native(token: String, core: MobileClient, operation: @escaping () async throws -> Data) {
        guard foreground, hardwareReady, core.requestIsPending(token: token) else { return }
        nativeTasks[token] = Task {
            defer { nativeTasks[token] = nil }
            do {
                guard !Task.isCancelled, foreground, hardwareReady, client === core, core.requestIsPending(token: token) else { return }
                let response = try await operation()
                guard !Task.isCancelled, foreground, hardwareReady, core.requestIsPending(token: token) else { return }
                try core.respond(token: token, data: response, accepted: true)
            } catch {
                if core.requestIsPending(token: token) {
                    if case HardwareError.cardNotPresent = error {
                        try? core.cardNotPresent(token: token)
                        return
                    }
                    if !cardInspection.isReading {
                        if case HardwareError.unavailable = error { show(error) }
                        if case HardwareError.multipleCards = error { show(error) }
                    }
                    try? core.failNativeRequest(token: token, message: error.localizedDescription, canceled: CardHardware.isUserCancellation(error))
                }
            }
        }
    }
    func perform(_ action: () async throws -> Void) async {
        busy = true
        defer { busy = false }
        do { try await action() } catch { show(error) }
    }
    func show(_ error: Error) {
        if case let MobileError.Failed(message) = error { self.error = message }
        else { self.error = error.localizedDescription }
    }
}
