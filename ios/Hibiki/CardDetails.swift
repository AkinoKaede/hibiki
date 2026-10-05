import SwiftUI

struct CardInspectionView: View {
    @Bindable var model: AppModel
    private var inspection: CardInspection { model.cardInspection }

    var body: some View {
        Section {
            if model.nfcAvailable {
                Picker("Read using", selection: Binding(get: { inspection.transport }, set: { inspection.select($0) })) {
                    Text("USB").tag(CardTransport.usb)
                    Text("NFC").tag(CardTransport.nfc)
                }.pickerStyle(.segmented).accessibilityIdentifier("inspectionTransport")
            }
            if inspection.transport == .usb {
                Label(model.usbPresent ? "USB Security Key Detected" : "No USB Security Key", systemImage: "cable.connector")
                Text("USB and Lightning connectors are supported.").font(.caption).foregroundStyle(.secondary)
            } else {
                Label("Tap to read public information using NFC.", systemImage: "wave.3.right")
            }
            Button { inspection.refresh() } label: {
                HStack {
                    Text(inspection.transport == .usb ? "Refresh USB Information" : "Read NFC Information")
                    Spacer()
                    if inspection.isReading { ProgressView() }
                }
            }
            .disabled(model.busy || inspection.isReading || (inspection.transport == .usb && !model.usbPresent))
            .accessibilityIdentifier("readSecurityKeyInfo")
            if let error = inspection.error { Text(verbatim: error).foregroundStyle(.red) }
        } header: { Text("Security Key Reader") } footer: {
            Text("Reading public information does not record this key for use. No PIN needed.")
        }
        if let info = inspection.info {
            Section {
                CardIdentityFields(info: info)
            } header: { Text("Security Key Information") } footer: {
                if inspection.transport == .nfc {
                    Text("NFC snapshot from the last read. The key is not continuously connected.")
                } else {
                    Text("Information from the last successful USB read. Kept until new information is read.")
                }
            }
            Section("OpenPGP Keys") { CardPublicKeyRows(keys: info.keys) }
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
            LabeledContent("Card Number", value: formatCardNumber(serial: info.serial))
            LabeledContent("Serial Number", value: identity.serial)
            LabeledContent("OpenPGP Version", value: identity.version)
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
