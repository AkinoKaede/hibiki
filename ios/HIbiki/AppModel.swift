import DeviceKit
import SwiftUI
import Observation

@MainActor @Observable
final class AppModel {
    var client: MobileClient?
    var device: DeviceInfo?
    var channels: [ChannelInfo] = []
    var card: CardInfo?
    var registeredCards: [RegisteredCard] = []
    var connection = "offline"
    var error: String?
    var busy = false
    var prompts: [PinPrompt] = []
    var usbPresent = false
    var foreground = true
    var server = UserDefaults.standard.string(forKey: "server") ?? "wss://hibiki.akinokaede.com/hibiki"
    var name = UserDefaults.standard.string(forKey: "deviceName") ?? Device.current.realDevice.description
    var skipTLSCertificateValidation = UserDefaults.standard.bool(forKey: "skipTLSCertificateValidation")
    var pinEnabled = UserDefaults.standard.bool(forKey: "pinEnabled")
    var cardEnabled = UserDefaults.standard.bool(forKey: "cardEnabled")
    var initialized = false
    var pairing: JoinInfo?
    private let hardware = CardHardware()
    private var eventTask: Task<Void, Never>?
    private var pollingTask: Task<Void, Never>?
    private var nativeTasks: [String: Task<Void, Never>] = [:]
    private var lifecycleTask: Task<Void, Never>?

    var currentPrompt: PinPrompt? { prompts.first }
    var selectedWiredAvailable: Bool {
        usbPresent && registeredCards.contains { $0.card.serial == card?.serial && $0.usbEnabled }
    }
    var statusText: String {
        switch connection {
        case "online": return String(localized: "Online")
        case "connecting": return String(localized: "Connecting")
        default: return String(localized: "Offline")
        }
    }
    func restore() async {
        guard UserDefaults.standard.string(forKey: "server") != nil, !server.isEmpty else { return }
        do {
            if let identity = try SecureStorage.identity() {
                try configure(identity: identity)
                await activate()
            }
        } catch { show(error) }
    }
    func setup() async {
        await perform {
            guard !self.server.isEmpty, !self.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return }
            // A previous interrupted setup may already have saved an identity; never replace it.
            var identity = try SecureStorage.identity()
            if identity == nil {
                let generated = try createIdentity(name: self.name)
                // Validate the relay before committing the first identity.
                _ = try MobileClient(directory: SecureStorage.directory().path, server: self.server, identity: generated, skipTlsCertificateValidation: self.skipTLSCertificateValidation)
                try SecureStorage.saveIdentity(generated)
                identity = generated
            }
            try self.configure(identity: identity!)
            UserDefaults.standard.set(self.server, forKey: "server")
            UserDefaults.standard.set(self.name, forKey: "deviceName")
            UserDefaults.standard.set(self.skipTLSCertificateValidation, forKey: "skipTLSCertificateValidation")
            await self.activate()
        }
    }
    private func configure(identity: Data) throws {
        let core = try MobileClient(directory: SecureStorage.directory().path, server: server, identity: identity, skipTlsCertificateValidation: skipTLSCertificateValidation)
        client = core
        device = try core.device()
        card = core.selectedCard()
        registeredCards = core.registeredCards()
        initialized = true
        core.setServices(pinentry: pinEnabled, card: cardEnabled)
        eventTask?.cancel()
        eventTask = Task { [weak self] in
            while !Task.isCancelled, let event = await core.nextEvent() {
                guard let self else { return }
                self.handle(event, core: core)
            }
        }
    }
    func sceneChanged(_ phase: ScenePhase) {
        // NFC and system sheets can make the scene inactive without backgrounding it.
        guard phase != .inactive else { return }
        foreground = phase == .active
        let previous = lifecycleTask
        lifecycleTask = Task {
            await previous?.value
            if phase == .background { await deactivate() }
            else if foreground { await activate() }
        }
    }
    func activate() async {
        guard foreground, let client else { return }
        do { try await client.start() } catch { show(error) }
        pollingTask?.cancel()
        pollingTask = Task {
            while !Task.isCancelled {
                let available = await hardware.usbAvailable()
                usbPresent = available
                client.usbPresent(present: available)
                await refresh()
                try? await Task.sleep(for: .seconds(3))
            }
        }
    }
    func deactivate() async {
        pollingTask?.cancel(); pollingTask = nil
        prompts.removeAll()
        nativeTasks.values.forEach { $0.cancel() }; nativeTasks.removeAll()
        await hardware.closeAll()
        await client?.stop()
        connection = "offline"
    }
    func refresh() async {
        guard let client, foreground else { return }
        card = client.selectedCard()
        registeredCards = client.registeredCards()
        do {
            channels = try await client.channels()
            if let pairing, channels.contains(where: { $0.id == pairing.channel && $0.active }) { self.pairing = nil }
        } catch { /* The connection state communicates transient relay failures. */ }
    }
    func updateServices() {
        client?.setServices(pinentry: pinEnabled, card: cardEnabled)
        UserDefaults.standard.set(pinEnabled, forKey: "pinEnabled")
        UserDefaults.standard.set(cardEnabled, forKey: "cardEnabled")
    }
    func register(_ transport: CardTransport, name: String, usbSupported: Bool, nfcSupported: Bool) async -> Bool {
        busy = true
        defer { busy = false }
        do {
            guard let client else { return false }
            _ = try await client.registerCard(transport: transport, name: name, usbSupported: usbSupported, nfcSupported: nfcSupported)
            card = client.selectedCard()
            registeredCards = client.registeredCards()
            return true
        } catch { show(error); return false }
    }
    func selectCard(_ serial: String) async {
        await perform {
            try await self.client?.selectCard(serial: serial)
            await self.refresh()
        }
    }
    func removeCard(_ serial: String) async {
        await perform {
            try await self.client?.removeCard(serial: serial)
            await self.refresh()
        }
    }
    func answer(_ prompt: PinPrompt, text: String = "", accepted: Bool) {
        guard let client else { return }
        defer { prompts.removeAll { $0.token == prompt.token } }
        do { try client.respond(token: prompt.token, data: Data(text.utf8), accepted: accepted) }
        catch { if client.requestIsPending(token: prompt.token) { show(error) } }
    }
    private func handle(_ event: NativeEvent, core: MobileClient) {
        switch event {
        case .connection(let state): connection = state
        case .prompt(let prompt):
            guard foreground, core.requestIsPending(token: prompt.token) else { return }
            prompts.append(prompt)
        case .cancelled(let token):
            prompts.removeAll { $0.token == token }
            nativeTasks.removeValue(forKey: token)?.cancel()
            Task { await hardware.cancel(token: token) }
        case .cardChanged: self.card = core.selectedCard(); registeredCards = core.registeredCards()
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
                    if case HardwareError.unavailable = error { show(error) }
                    if case HardwareError.multipleCards = error { show(error) }
                    try? core.respond(token: token, data: Data(), accepted: false)
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
