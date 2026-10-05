import SwiftUI

struct CardInspectionView: View {
    @Bindable var model: AppModel
    private var inspection: CardInspection { model.cardInspection }

    var body: some View {
        Section {
            Picker("Read using", selection: Binding(get: { inspection.transport }, set: { inspection.select($0) })) {
                Text("USB").tag(CardTransport.usb)
                Text("NFC").tag(CardTransport.nfc)
            }.pickerStyle(.segmented).accessibilityIdentifier("inspectionTransport")
            if inspection.transport == .usb {
                Label(model.usbPresent ? "USB security key detected" : "No USB security key", systemImage: "cable.connector")
                Text("USB and Lightning connectors are supported.").font(.caption).foregroundStyle(.secondary)
            } else {
                Label("Tap to read public information using NFC.", systemImage: "wave.3.right")
            }
            Button { inspection.refresh() } label: {
                HStack {
                    Text(inspection.transport == .usb ? "Refresh USB information" : "Read NFC information")
                    Spacer()
                    if inspection.isReading { ProgressView() }
                }
            }
            .disabled(model.busy || inspection.isReading || (inspection.transport == .usb && !model.usbPresent))
            .accessibilityIdentifier("readSecurityKeyInfo")
            if let error = inspection.error { Text(verbatim: error).foregroundStyle(.red) }
        } header: { Text("Security key reader") } footer: {
            Text("Reading public information does not register or select this security key. No PIN needed.")
        }
        if let info = inspection.info {
            Section {
                if let entry = model.registeredCards.first(where: { $0.card.serial == info.serial }) {
                    LabeledContent("Name", value: entry.name)
                }
                CardIdentityFields(info: info)
            } header: { Text("Security key information") } footer: {
                if inspection.transport == .nfc {
                    Text("NFC snapshot from the last read. The key is not continuously connected.")
                }
            }
            Section("OpenPGP keys") { CardPublicKeyRows(keys: info.keys) }
        }
    }
}

struct CardIdentityFields: View {
    let info: CardInfo
    var body: some View {
        LabeledContent("OpenPGP AID") {
            Text(verbatim: info.serial).font(.caption.monospaced()).textSelection(.enabled)
        }
        if let identity = OpenPGPIdentity(aid: info.serial) {
            LabeledContent("Card number", value: identity.manufacturer + " " + identity.serial)
            LabeledContent("Serial number", value: identity.serial)
            LabeledContent("OpenPGP version", value: identity.version)
            LabeledContent("Manufacturer ID", value: identity.manufacturer)
        }
    }
}

struct CardPublicKeyRows: View {
    let keys: [CardKey]
    var body: some View {
        if keys.isEmpty { Text("No OpenPGP keys found on this key").foregroundStyle(.secondary) }
        ForEach(keys) { key in
            VStack(alignment: .leading, spacing: 6) {
                Text(key.slot == 1 ? "Signing" : (key.slot == 2 ? "Decryption" : "Authentication")).font(.headline)
                LabeledContent("Algorithm", value: key.algorithm)
                if !key.fingerprint.isEmpty {
                    Text("Fingerprint").font(.caption).foregroundStyle(.secondary)
                    Text(verbatim: key.fingerprint).font(.caption.monospaced()).textSelection(.enabled)
                }
                if !key.keygrip.isEmpty {
                    Text("Keygrip").font(.caption).foregroundStyle(.secondary)
                    Text(verbatim: key.keygrip).font(.caption.monospaced()).textSelection(.enabled)
                }
                if key.createdAt > 0 {
                    LabeledContent("Created") {
                        Text(Date(timeIntervalSince1970: TimeInterval(key.createdAt)), format: .dateTime.year().month().day().hour().minute())
                    }
                }
            }.padding(.vertical, 4)
        }
    }
}

struct EditRegisteredCardView: View {
    let entry: RegisteredCard
    @Bindable var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var name: String
    @State private var usbSupported: Bool
    @State private var nfcSupported: Bool
    @State private var saving = false
    @State private var error: String?

    init(entry: RegisteredCard, model: AppModel) {
        self.entry = entry
        self.model = model
        _name = State(initialValue: entry.name)
        _usbSupported = State(initialValue: entry.usbEnabled)
        _nfcSupported = State(initialValue: entry.nfcEnabled)
    }

    private var valid: Bool {
        !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && (usbSupported || nfcSupported)
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("Security key") {
                    TextField("Name", text: $name).accessibilityIdentifier("securityKeyName")
                    Toggle("USB", isOn: $usbSupported).accessibilityIdentifier("securityKeyUSB")
                    Toggle("NFC", isOn: $nfcSupported).accessibilityIdentifier("securityKeyNFC")
                }.disabled(saving)
                Section {
                    if name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                        Text("Enter a security key name.").foregroundStyle(.red)
                    }
                    if !usbSupported && !nfcSupported {
                        Text("Enable at least one connection.").foregroundStyle(.red)
                    }
                    if let error { Text(verbatim: error).foregroundStyle(.red) }
                } footer: {
                    Text("Choose the connections this key supports. Saving does not read or change the physical key.")
                }
            }
            .navigationTitle("Edit security key")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }.disabled(saving)
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        saving = true
                        error = nil
                        Task {
                            defer { saving = false }
                            do {
                                try await model.updateCard(entry.id, name: name, usbSupported: usbSupported, nfcSupported: nfcSupported)
                                dismiss()
                            } catch {
                                if case MobileError.Failed(let message) = error {
                                    self.error = message == "card is in use" ? String(localized: "Security key is in use. Try again when the operation finishes.") : message
                                } else { self.error = error.localizedDescription }
                            }
                        }
                    }.disabled(!valid || saving || model.busy).accessibilityIdentifier("saveSecurityKey")
                }
            }
            .interactiveDismissDisabled(saving)
        }
    }
}
