import Foundation
@preconcurrency import CryptoTokenKit
@preconcurrency import CoreNFC

enum HardwareError: LocalizedError {
    case cardNotPresent, unavailable, disconnected, multipleCards, invalidResponse
    var errorDescription: String? {
        switch self {
        case .cardNotPresent: return String(localized: "Security key is not connected.")
        case .unavailable:
            return String(localized: "Security key reader is unavailable. Check permissions and try again.")
        case .disconnected: return String(localized: "Security key disconnected or operation canceled.")
        case .multipleCards: return String(localized: "Connect only the security key you want to use.")
        case .invalidResponse: return String(localized: "Invalid security key response.")
        }
    }
}

protocol CardHardwareAccess: Sendable {
    func usbState() async -> USBState
    func usbEvents() async -> AsyncStream<USBState>
    func open(id: String, token: String, transport: CardTransport) async throws -> Data
    func transmit(id: String, token: String, command: Data) async throws -> Data
    func cancel(token: String) async
    func close(id: String) async
    func closeAll() async
}

/// Native card objects never leave this actor. Rust owns the OpenPGP protocol.
actor CardHardware: CardHardwareAccess {
    nonisolated static var nfcReadingAvailable: Bool { NFCTagReaderSession.readingAvailable }
    nonisolated static func isUserCancellation(_ error: Error) -> Bool {
        if error is CancellationError { return true }
        return (error as? NFCReaderError)?.code == .readerSessionInvalidationErrorUserCanceled
    }
    private var connection: String?
    private var operation: String?
    private var usb: TKSmartCard?
    private var nfc: NFCReader?

    private let usbMonitor = USBMonitor()
    func usbState() -> USBState { usbMonitor.snapshot() }
    func usbEvents() -> AsyncStream<USBState> { usbMonitor.events() }

    func open(id: String, token: String, transport: CardTransport) async throws -> Data {
        closeAll()
        connection = id
        operation = token
        do {
            var insertion: String?
            switch transport {
            case .usb:
                guard let manager = TKSmartCardSlotManager.default else { throw HardwareError.unavailable }
                let slots = manager.slotNames.compactMap { manager.slotNamed($0) }.filter { $0.state == .validCard }
                guard slots.count <= 1 else { throw HardwareError.multipleCards }
                guard let slot = slots.first,
                      let identity = usbMonitor.connection(for: slot.name),
                      let card = slot.makeSmartCard() else { throw HardwareError.cardNotPresent }
                insertion = identity
                card.isSensitive = true
                usb = card
                try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                    card.beginSession { success, error in
                        if success { continuation.resume() }
                        else { continuation.resume(throwing: error ?? HardwareError.disconnected) }
                    }
                }
            case .nfc:
                let reader = NFCReader()
                nfc = reader
                try await reader.open()
            }
            guard connection == id, operation == token, !Task.isCancelled else { throw HardwareError.disconnected }
            operation = nil
            if let insertion {
                guard usbMonitor.snapshot().connections.contains(insertion) else { throw HardwareError.disconnected }
                return Data(insertion.utf8)
            }
            return Data()
        } catch {
            if connection == id { closeAll() }
            throw error
        }
    }

    func transmit(id: String, token: String, command: Data) async throws -> Data {
        guard connection == id, !Task.isCancelled else { throw HardwareError.disconnected }
        operation = token
        defer { if operation == token { operation = nil } }
        let reply: Data
        if let card = usb {
            reply = try await withCheckedThrowingContinuation { continuation in
                card.transmit(command) { data, error in
                    if let data { continuation.resume(returning: data) }
                    else { continuation.resume(throwing: error ?? HardwareError.disconnected) }
                }
            }
        } else if let nfc {
            reply = try await nfc.transmit(command)
        } else { throw HardwareError.disconnected }
        guard connection == id, !Task.isCancelled else { throw HardwareError.disconnected }
        return reply
    }

    func cancel(token: String) { if operation == token { closeAll() } }
    func close(id: String) { if connection == id { closeAll() } }
    func closeAll() {
        connection = nil
        operation = nil
        usb?.endSession()
        usb = nil
        nfc?.close()
        nfc = nil
    }
}

/// Core NFC calls its delegate on a private serial queue; a lock protects cancellation.
private struct NFCTagBox: @unchecked Sendable { let value: any NFCISO7816Tag }

final class NFCReader: NSObject, NFCTagReaderSessionDelegate, @unchecked Sendable {
    private let lock = NSLock()
    private var session: NFCTagReaderSession?
    private var tag: (any NFCISO7816Tag)?
    private var opening: CheckedContinuation<Void, Error>?
    private var closed = false

    func open() async throws {
        guard NFCTagReaderSession.readingAvailable else { throw HardwareError.unavailable }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            lock.lock()
            guard !closed else { lock.unlock(); continuation.resume(throwing: HardwareError.disconnected); return }
            opening = continuation
            let reader = NFCTagReaderSession(pollingOption: .iso14443, delegate: self, queue: nil)
            reader?.alertMessage = String(localized: "Hold your security key near the top of your iPhone until the operation finishes.")
            session = reader
            lock.unlock()
            guard let reader else { finish(HardwareError.unavailable); return }
            reader.begin()
        }
    }
    func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {}
    func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        lock.lock(); closed = true; tag = nil; lock.unlock()
        finish(error)
    }
    func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        guard tags.count == 1, case .iso7816(let card) = tags[0] else {
            session.alertMessage = String(localized: "Hold only one OpenPGP security key near your iPhone.")
            session.restartPolling()
            return
        }
        let box = NFCTagBox(value: card)
        session.connect(to: tags[0]) { [weak self] error in
            guard let self else { return }
            if let error { self.finish(error); return }
            self.lock.lock()
            if !self.closed { self.tag = box.value }
            let wasClosed = self.closed
            self.lock.unlock()
            self.finish(wasClosed ? HardwareError.disconnected : nil)
        }
    }
    private func finish(_ error: Error?) {
        lock.lock(); let continuation = opening; opening = nil; lock.unlock()
        if let error { continuation?.resume(throwing: error) } else { continuation?.resume() }
    }
    func transmit(_ bytes: Data) async throws -> Data {
        let card: (any NFCISO7816Tag)? = lock.withLock { tag }
        guard let card, let command = NFCISO7816APDU(data: bytes) else { throw HardwareError.disconnected }
        return try await withCheckedThrowingContinuation { continuation in
            card.sendCommand(apdu: command) { data, sw1, sw2, error in
                if let error { continuation.resume(throwing: error) }
                else { continuation.resume(returning: data + Data([sw1, sw2])) }
            }
        }
    }
    func close() {
        lock.lock(); closed = true; tag = nil; let reader = session; session = nil; lock.unlock()
        finish(HardwareError.disconnected)
        reader?.invalidate()
    }
}

/// Immutable insertion identities also detect replacement while overall availability stays true.
struct USBState: Sendable, Equatable {
    var revision: UInt64 = 0
    var connections: [String] = []
}

/// Pure transition state: slot names identify readers; UUIDs identify insertions.
struct USBInsertions {
    private(set) var identities: [String: String] = [:]
    private var revision: UInt64 = 0
    var state: USBState { USBState(revision: revision, connections: identities.values.sorted()) }

    @discardableResult
    mutating func update(name: String, present: Bool) -> Bool {
        guard present != (identities[name] != nil) else { return false }
        identities[name] = present ? UUID().uuidString : nil
        revision += 1
        return true
    }
}

/// KVO callbacks run on system queues. Serialize transitions before handing them to Swift tasks.
final class USBMonitor: @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private let manager: TKSmartCardSlotManager?
    private var managerObservation: NSKeyValueObservation?
    private var slots: [String: (TKSmartCardSlot, NSKeyValueObservation)] = [:]
    private var insertions = USBInsertions()
    private var listeners: [UUID: AsyncStream<USBState>.Continuation] = [:]

    init() {
        manager = TKSmartCardSlotManager.default
        managerObservation = manager?.observe(\.slotNames, options: [.new]) { [weak self] _, _ in
            self?.rescan()
        }
        rescan()
    }

    deinit {
        managerObservation?.invalidate()
        for (_, observation) in slots.values { observation.invalidate() }
        for continuation in listeners.values { continuation.finish() }
    }

    func snapshot() -> USBState {
        lock.withLock {
            rescan()
            return current
        }
    }
    func connection(for name: String) -> String? {
        lock.withLock { rescan(); return insertions.identities[name] }
    }
    func events() -> AsyncStream<USBState> {
        let id = UUID()
        return AsyncStream { continuation in
            lock.withLock {
                rescan()
                listeners[id] = continuation
                continuation.yield(current)
            }
            continuation.onTermination = { [weak self] _ in
                self?.removeListener(id)
            }
        }
    }
    private func removeListener(_ id: UUID) { lock.withLock { _ = listeners.removeValue(forKey: id) } }
    private var current: USBState { insertions.state }

    private func rescan() {
        lock.withLock {
            let names = Set(manager?.slotNames ?? [])
            for name in Array(slots.keys) where !names.contains(name) {
                slots.removeValue(forKey: name)?.1.invalidate()
                update(name: name, present: false)
            }
            for name in names {
                if slots[name] == nil, let slot = manager?.slotNamed(name) {
                    let observation = slot.observe(\.state, options: [.new]) { [weak self] slot, change in
                        guard let state = change.newValue else { return }
                        self?.changed(name: name, slot: slot, present: state == .validCard)
                    }
                    slots[name] = (slot, observation)
                }
                if let slot = slots[name]?.0 { update(name: name, present: slot.state == .validCard) }
            }
        }
    }
    private func changed(name: String, slot: TKSmartCardSlot, present: Bool) {
        lock.withLock {
            guard slots[name]?.0 === slot else { return }
            update(name: name, present: present)
        }
    }
    private func update(name: String, present: Bool) {
        guard insertions.update(name: name, present: present) else { return }
        let state = current
        for continuation in listeners.values { continuation.yield(state) }
    }
}
