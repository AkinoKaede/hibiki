import DeviceKit
import SwiftUI
import Observation

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
    private let hardware = CardHardware()
    private var eventTask: Task<Void, Never>?
    private var pollingTask: Task<Void, Never>?
    private var nativeTasks: [String: Task<Void, Never>] = [:]
    private var lifecycleTask: Task<Void, Never>?
    private var disconnecting = false

    private let defaults: UserDefaults
    private let resetRelayStorage: () throws -> Void

    init(defaults: UserDefaults = .standard, resetRelayStorage: @escaping () throws -> Void = SecureStorage.resetRelay, nfcCapability: @escaping () -> Bool = { CardHardware.nfcReadingAvailable }) {
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

    var currentPrompt: PinPrompt? { prompts.first }
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
        await perform {
            guard let core = self.client else { return }
            let identity = try await core.renameDevice(name: newName)
            try SecureStorage.saveIdentity(identity)
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
        // NFC and system sheets can make the scene inactive without backgrounding it.
        guard phase != .inactive else { return }
        foreground = phase == .active
        if foreground { refreshHardwareCapabilities() }
        else { cardInspection.setActive(false); nfcReadCancellation?.cancel() }
        guard !disconnecting else { return }
        let previous = lifecycleTask
        lifecycleTask = Task {
            await previous?.value
            if phase == .background { await deactivate() }
            else if foreground { await activate() }
        }
    }
    func activate() async {
        guard foreground, !disconnecting, let client else { return }
        do { try await client.start() } catch { show(error) }
        guard foreground, !disconnecting, self.client === client else { return }
        cardInspection.setActive(true)
        pollingTask?.cancel()
        pollingTask = Task {
            while !Task.isCancelled {
                await refreshUSBAvailability()
                await refresh()
                try? await Task.sleep(for: .seconds(3))
            }
        }
    }
    func refreshUSBAvailability() async {
        guard let client else { return }
        let present = await hardware.usbAvailable()
        guard self.client === client, !Task.isCancelled else { return }
        usbPresent = present
        cardInspection.usbChanged(present)
        client.usbPresent(present: present)
    }
    func deactivate() async {
        cardInspection.setActive(false)
        pollingTask?.cancel(); pollingTask = nil
        prompts.removeAll()
        nativeTasks.values.forEach { $0.cancel() }; nativeTasks.removeAll()
        await hardware.closeAll()
        await client?.stop()
        connection = "offline"
        allowChannelCreation = nil
    }
    func refresh() async {
        guard let client, foreground else { return }
        recordedNFCCard = client.nfcCard()
        do {
            let channels = try await client.channels()
            guard self.client === client, !Task.isCancelled else { return }
            self.channels = channels
            if connection == "online" {
                let allowed = try await client.allowsChannelCreation()
                guard self.client === client, !Task.isCancelled, connection == "online" else { return }
                allowChannelCreation = allowed
                if let pairing, !busy {
                    let state = try await client.pairingStatus(channel: pairing.channel, requestId: pairing.request)
                    guard self.client === client, !Task.isCancelled, !busy, self.pairing?.request == pairing.request else { return }
                    switch state {
                    case .member: rememberPairing(nil)
                    case .absent:
                        rememberPairing(nil)
                        error = String(localized: "This join request was rejected or has expired. Get a new invitation to try again.")
                    case .pending: break
                    }
                }
            }
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
        guard !busy, foreground, let client else { return }
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
        guard !busy, foreground, let client else { throw CancellationError() }
        busy = true
        let cancellation = CardReadCancellation()
        nfcReadCancellation = cancellation
        defer {
            busy = false
            nfcReadCancellation = nil
            if !client.requestIsPending(token: prompt.token) { prompts.removeAll { $0.token == prompt.token } }
        }
        await refreshUSBAvailability()
        guard foreground, self.client === client, client.requestIsPending(token: prompt.token) else { throw CancellationError() }
        try await client.continueCardInsertion(prompt: prompt, cancellation: cancellation)
        recordedNFCCard = client.nfcCard()
        prompts.removeAll { $0.token == prompt.token }
    }
    func showCardInspection() {
        refreshHardwareCapabilities()
        cardInspection.appear(usbPresent: usbPresent, active: foreground) { [weak self] transport in
            guard let core = self?.client else { throw CancellationError() }
            let cancellation = CardReadCancellation()
            return try await withTaskCancellationHandler {
                try Task.checkCancellation()
                return try await core.inspectCard(transport: transport, cancellation: cancellation)
            } onCancel: { cancellation.cancel() }
        }
    }
    func answer(_ prompt: PinPrompt, text: String = "", accepted: Bool) {
        defer { prompts.removeAll { $0.token == prompt.token } }
        guard let client else { return }
        do { try client.respond(token: prompt.token, data: Data(text.utf8), accepted: accepted) }
        catch { if client.requestIsPending(token: prompt.token) { show(error) } }
    }
    func cancelPrompt(_ prompt: PinPrompt) {
        defer { prompts.removeAll { $0.token == prompt.token } }
        guard let client else { return }
        do { try client.cancelRequest(token: prompt.token) }
        catch { if client.requestIsPending(token: prompt.token) { show(error) } }
    }
    private func handle(_ event: NativeEvent, core: MobileClient) {
        switch event {
        case .connection(let state):
            connection = state
            if state != "online" { allowChannelCreation = nil }
        case .prompt(let prompt):
            guard foreground, core.requestIsPending(token: prompt.token) else { return }
            prompts.append(prompt)
        case .cancelled(let token):
            prompts.removeAll { $0.token == token }
            nativeTasks.removeValue(forKey: token)?.cancel()
            Task { await hardware.cancel(token: token) }
        case .cardChanged: recordedNFCCard = core.nfcCard()
        case .cardClose(let id): Task { await hardware.close(id: id) }
        case .cardOpen(let token, let id, let transport):
            native(token: token, core: core) { try await self.hardware.open(id: id, token: token, transport: transport); return Data() }
        case .cardTransmit(let token, let id, let command):
            native(token: token, core: core) { try await self.hardware.transmit(id: id, token: token, command: command) }
        }
    }
    private func native(token: String, core: MobileClient, operation: @escaping () async throws -> Data) {
        guard foreground, core.requestIsPending(token: token) else { return }
        nativeTasks[token] = Task {
            defer { nativeTasks[token] = nil }
            do {
                let response = try await operation()
                guard !Task.isCancelled, foreground, core.requestIsPending(token: token) else { return }
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
