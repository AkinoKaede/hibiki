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
    func usbAvailable() async -> Bool
    func open(id: String, token: String, transport: CardTransport) async throws
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

    func usbAvailable() -> Bool {
        TKSmartCardSlotManager.default?.slotNames.contains { name in
            TKSmartCardSlotManager.default?.slotNamed(name)?.state == .validCard
        } ?? false
    }

    func open(id: String, token: String, transport: CardTransport) async throws {
        closeAll()
        connection = id
        operation = token
        do {
            switch transport {
            case .usb:
                guard let manager = TKSmartCardSlotManager.default else { throw HardwareError.unavailable }
                let slots = manager.slotNames.compactMap { manager.slotNamed($0) }.filter { $0.state == .validCard }
                guard slots.count <= 1 else { throw HardwareError.multipleCards }
                guard let card = slots.first?.makeSmartCard() else { throw HardwareError.cardNotPresent }
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
