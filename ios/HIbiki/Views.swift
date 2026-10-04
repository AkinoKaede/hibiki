import SwiftUI

extension PinPrompt: Identifiable { public var id: String { token } }
extension CardKey: Identifiable { public var id: UInt8 { slot } }
extension ChannelInfo: Identifiable {}
extension DeviceInfo: Identifiable {}
extension PendingInfo: Identifiable {}

struct RootView: View {
    @Bindable var model: AppModel
    var body: some View {
        Group {
            if model.initialized {
                TabView {
                    NavigationStack { StatusView(model: model) }.tabItem { Label("Status", systemImage: "waveform") }
                    NavigationStack { ChannelsView(model: model) }.tabItem { Label("Channels", systemImage: "person.2") }
                    NavigationStack { CardView(model: model) }.tabItem { Label("Security Keys", systemImage: "key.horizontal") }
                    NavigationStack { SettingsView(model: model) }.tabItem { Label("Settings", systemImage: "gearshape") }
                }
            } else { NavigationStack { SetupView(model: model) } }
        }
        .overlay {
            if !model.foreground {
                ZStack {
                    Color(uiColor: .systemBackground).ignoresSafeArea()
                    Label("HIbiki", systemImage: "lock.shield").font(.title)
                }.accessibilityHidden(true)
            }
        }
        .tint(.indigo)
        .sheet(item: Binding(get: { model.currentPrompt }, set: { value in
            if value == nil, let prompt = model.currentPrompt { model.answer(prompt, accepted: false) }
        })) { prompt in
            PinView(prompt: prompt, model: model).id(prompt.token).interactiveDismissDisabled()
        }
        .alert("Unable to complete", isPresented: Binding(get: { model.error != nil }, set: { if !$0 { model.error = nil } })) {
            Button("OK", role: .cancel) { model.error = nil }
        } message: { Text(verbatim: model.error ?? "") }
    }
}

struct SetupView: View {
    @Bindable var model: AppModel
    var body: some View {
        Form {
            Section {
                Image(systemName: "waveform.circle.fill").font(.system(size: 64)).foregroundStyle(.indigo).frame(maxWidth: .infinity).padding()
                Text("Your keys stay with you.").font(.title2.bold())
                Text("Enter passwords and use your security key for GPG operations on your trusted computers.").foregroundStyle(.secondary)
            }
            Section("Connect to your relay") {
                TextField("wss://hibiki.akinokaede.com/hibiki", text: $model.server).keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled().accessibilityIdentifier("relayURL")
                TextField("Device name", text: $model.name).accessibilityIdentifier("deviceName")
            }
            Section {
                DisclosureGroup("Advanced") {
                    Toggle("Skip TLS Certificate Validation", isOn: $model.skipTLSCertificateValidation)
                }
            }
            Section {
                Button { Task { await model.setup() } } label: {
                    HStack { Text("Get started"); Spacer(); if model.busy { ProgressView() } else { Image(systemName: "arrow.right") } }
                }.disabled(model.busy || model.server.isEmpty || model.name.isEmpty).accessibilityIdentifier("getStarted")
            } footer: { Text("HIbiki connects while the app is open. Services are off until you enable them.") }
        }.navigationTitle("HIbiki")
    }
}

struct StatusView: View {
    @Bindable var model: AppModel
    var body: some View {
        List {
            Section {
                HStack(spacing: 16) {
                    Image(systemName: model.connection == "online" ? "checkmark.shield.fill" : "network.slash").font(.largeTitle).foregroundStyle(model.connection == "online" ? .green : .secondary)
                    VStack(alignment: .leading, spacing: 5) { Text(model.statusText).font(.title2.bold()); Text(verbatim: model.device?.name ?? "HIbiki").foregroundStyle(.secondary) }
                }.padding(.vertical, 12)
                LabeledContent("Relay") { Text(verbatim: model.server).font(.caption).lineLimit(2) }
            }
            Section("Provide services") {
                Toggle("Password entry", isOn: $model.pinEnabled).onChange(of: model.pinEnabled) { _, _ in model.updateServices() }
                Toggle("OpenPGP card", isOn: $model.cardEnabled).onChange(of: model.cardEnabled) { _, _ in model.updateServices() }
                if model.cardEnabled, model.card == nil { Text("Register your security key in the Security Keys tab.").foregroundStyle(.secondary) }
                if let card = model.card, model.cardEnabled {
                    Label(model.selectedUSBAvailable ? "USB connection detected" : (card.transport == .nfc ? (model.selectedUSBSupported ? "Connect using USB, or enter the PIN and use NFC." : "Enter the PIN, then tap your security key using NFC.") : "Confirmation required for each operation"), systemImage: model.selectedUSBAvailable || card.transport == .usb ? "cable.connector" : "wave.3.right")
                }
            }
            if let pairing = model.pairing {
                Section("Waiting for approval") {
                    Text("Compare these words on an existing member device before approving.")
                    Text(verbatim: model.device?.words ?? "").font(.system(.body, design: .monospaced)).textSelection(.enabled)
                    LabeledContent("Request") { Text(verbatim: pairing.request).font(.caption).textSelection(.enabled) }
                    Text("This request stays pending until approved or invalidated.")
                }
            }
            Section {
                Label("Private keys remain on your security key.", systemImage: "lock.shield")
                Text("Keep HIbiki open to receive requests. Returning reconnects and accepts requests still waiting for this device.").foregroundStyle(.secondary)
            }
        }.navigationTitle("HIbiki").refreshable { await model.refresh() }
    }
}

struct ChannelsView: View {
    @Bindable var model: AppModel
    var body: some View {
        List {
            if model.channels.isEmpty {
                ContentUnavailableView("No channels yet", systemImage: "person.2", description: Text("Join a trusted device’s channel, or create your own."))
            }
            ForEach(model.channels) { channel in
                NavigationLink { ChannelView(channelID: channel.id, model: model) } label: {
                    VStack(alignment: .leading) {
                        Text(verbatim: channel.name).font(.headline)
                        Text(channel.active ? "Member" : "Not an active member").font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            Section {
                NavigationLink("Join a channel") { JoinView(model: model) }
                NavigationLink("Create a channel") { CreateChannelView(model: model) }
            }
        }.navigationTitle("Channels").refreshable { await model.refresh() }
    }
}

struct JoinView: View {
    @Bindable var model: AppModel
    @State private var invite = ""
    @State private var psk = ""
    var body: some View {
        Form {
            Section("Invitation") { TextField("hibiki-v1:…", text: $invite, axis: .vertical).textInputAutocapitalization(.never).autocorrectionDisabled() }
            Section("Channel PSK") { SecureField("Pre-shared key", text: $psk).textInputAutocapitalization(.never).autocorrectionDisabled() }
            Section {
                Button("Request to join") {
                    let secret = psk; psk = ""
                    Task { await model.perform {
                        model.pairing = try await model.client?.join(invitation: invite.trimmingCharacters(in: .whitespacesAndNewlines), psk: secret)
                        await model.refresh()
                    } }
                }.disabled(invite.isEmpty || psk.isEmpty || model.busy || model.connection != "online")
            } footer: { Text("Obtain the invitation and PSK separately from a trusted member. The invitation must use your configured relay.") }
            if let pairing = model.pairing {
                Section("Waiting for approval") {
                    Text(verbatim: model.device?.words ?? "").font(.system(.body, design: .monospaced)).textSelection(.enabled)
                    Text(verbatim: pairing.request).font(.caption).textSelection(.enabled)
                    Text("Compare all 24 words and the request ID on the approving device.")
                }
            }
        }.navigationTitle("Join channel").onDisappear { psk = "" }
    }
}

struct CreateChannelView: View {
    @Bindable var model: AppModel
    @State private var name = ""
    @State private var result: Invitation?
    var body: some View {
        Form {
            if let result { InvitationSections(invite: result.invite, psk: result.psk) }
            else {
                Section { TextField("Channel name", text: $name) }
                Button("Create channel") { Task { await model.perform {
                    result = try await model.client?.createChannel(name: name)
                    await model.refresh()
                } } }.disabled(name.isEmpty || model.busy || model.connection != "online")
            }
        }
        .navigationTitle("Create channel")
        .toolbar {
            if let result {
                ToolbarItem(placement: .topBarTrailing) {
                    ShareLink(item: result.invite) { Label("Share invitation", systemImage: "square.and.arrow.up") }
                        .labelStyle(.iconOnly)
                        .accessibilityIdentifier("shareInvitation")
                }
            }
        }
        .onDisappear { result = nil }
    }
}
struct InvitationSections: View {
    let invite: String
    let psk: String
    var body: some View {
        if !invite.isEmpty {
            Section("Invitation") {
                Text(verbatim: invite).font(.system(.caption, design: .monospaced)).lineLimit(5).textSelection(.enabled)
            }
        }
        if !psk.isEmpty {
            Section {
                Text(verbatim: psk).font(.system(.body, design: .monospaced)).textSelection(.enabled).privacySensitive()
                Button("Copy PSK") { UIPasteboard.general.setItems([[UIPasteboard.typeAutomatic: psk]], options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(120)]) }
            } header: { Text("Save your PSK") } footer: { Text("Store this PSK safely. Share it separately from the invitation; HIbiki does not save it.") }
        }
    }
}

struct InvitationShareSheet: UIViewControllerRepresentable {
    let invitation: String
    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: [invitation], applicationActivities: nil)
    }
    func updateUIViewController(_ controller: UIActivityViewController, context: Context) {}
}

struct ChannelView: View {
    let channelID: String
    @Bindable var model: AppModel
    @State private var pending: [PendingInfo] = []
    @State private var invitation = ""
    @State private var psk = ""
    @State private var revoke: DeviceInfo?
    @State private var leaving = false
    @State private var rotating = false
    private var channel: ChannelInfo? { model.channels.first { $0.id == channelID } }
    var body: some View {
        List {
            Section("Members") {
                ForEach(channel?.members ?? []) { device in
                    HStack {
                        VStack(alignment: .leading) { Text(verbatim: device.name); Text(device.online ? "Online" : "Offline").font(.caption).foregroundStyle(.secondary) }
                        Spacer()
                        if device.id != model.device?.id {
                            Button("Revoke", role: .destructive) { revoke = device }.buttonStyle(.borderless).disabled(model.connection != "online")
                        } else { Text("This device").font(.caption).foregroundStyle(.secondary) }
                    }
                }
            }
            if channel?.active == true {
                Section("Pending requests") {
                    if pending.isEmpty { Text("No pending requests").foregroundStyle(.secondary) }
                    ForEach(pending) { request in
                        NavigationLink { ApprovalView(request: request, model: model) } label: { Text(verbatim: request.device.name) }
                    }
                }
            }
            if !psk.isEmpty { InvitationSections(invite: "", psk: psk) }
            Section("Channel ID") { Text(verbatim: channelID).font(.caption.monospaced()).textSelection(.enabled) }
        }
        .navigationTitle(channel?.name ?? String(localized: "Channel"))
        .toolbar {
            if channel?.active == true {
                ToolbarItem(placement: .topBarTrailing) {
                    Menu {
                        Button {
                            Task { await model.perform { invitation = try await model.client?.invitation(channel: channelID) ?? "" } }
                        } label: { Label("Invite device", systemImage: "square.and.arrow.up") }
                        .accessibilityIdentifier("inviteDevice")
                        Button { rotating = true } label: { Label("Rotate PSK", systemImage: "arrow.triangle.2.circlepath") }
                        Divider()
                        Button(role: .destructive) { leaving = true } label: {
                            Label {
                                Text("Leave channel")
                            } icon: {
                                if let icon = UIImage(systemName: "rectangle.portrait.and.arrow.right") {
                                    Image(uiImage: icon.withTintColor(.systemRed, renderingMode: .alwaysOriginal))
                                        .renderingMode(.original)
                                }
                            }
                        }
                    } label: { Label("Channel actions", systemImage: "ellipsis") }
                    .disabled(model.connection != "online" || model.busy)
                    .accessibilityIdentifier("channelActions")
                }
            }
        }
        .sheet(isPresented: Binding(get: { !invitation.isEmpty }, set: { if !$0 { invitation = "" } })) {
            InvitationShareSheet(invitation: invitation)
                .presentationDetents([.medium, .large])
        }
        .task { await load() }.refreshable { await load() }
        .confirmationDialog("Revoke this device?", isPresented: Binding(get: { revoke != nil }, set: { if !$0 { revoke = nil } }), titleVisibility: .visible) {
            if let device = revoke { Button("Revoke", role: .destructive) { Task { await model.perform { try await model.client?.revoke(channel: channelID, device: device.id); await load() } } } }
        } message: { Text("This identity will no longer be able to rejoin this channel.") }
        .confirmationDialog("Leave this channel?", isPresented: $leaving, titleVisibility: .visible) {
            Button("Leave channel", role: .destructive) { Task { await model.perform { try await model.client?.leave(channel: channelID); await load() } } }
        }
        .confirmationDialog("Rotate channel PSK?", isPresented: $rotating, titleVisibility: .visible) {
            Button("Rotate PSK") { Task { await model.perform { psk = try await model.client?.rotatePsk(channel: channelID) ?? ""; await load() } } }
        } message: { Text("Pending requests will be invalidated. Approved members retain access.") }
        .onDisappear { psk = "" }
    }
    private func load() async {
        await model.refresh()
        if channel?.active == true { do { pending = try await model.client?.pending(channel: channelID) ?? [] } catch { model.show(error) } }
    }
}

struct ApprovalView: View {
    let request: PendingInfo
    @Bindable var model: AppModel
    @State private var verified = false
    @State private var approved = false
    var body: some View {
        Form {
            Section("Joining device") { Text(verbatim: request.device.name); Text(verbatim: request.device.id).font(.caption.monospaced()).textSelection(.enabled) }
            Section("Public-key verification words") { Text(verbatim: request.device.words).font(.system(.body, design: .monospaced)).textSelection(.enabled) }
            Section("Request ID") { Text(verbatim: request.id).font(.caption.monospaced()).textSelection(.enabled) }
            Section {
                Toggle("I compared all 24 words and the request ID", isOn: $verified)
                Button(approved ? "Approved" : "Approve device") { Task { await model.perform {
                    try await model.client?.approve(channel: request.channel, requestId: request.id)
                    approved = true; await model.refresh()
                } } }.disabled(!verified || approved || model.busy)
            } footer: { Text("These words identify a public device key. They are not a recovery phrase.") }
        }.navigationTitle("Approve device")
    }
}

extension RegisteredCard: Identifiable {
    public var id: String { card.serial }
    var connections: String { [usbEnabled ? String(localized: "USB") : nil, nfcEnabled ? "NFC" : nil].compactMap { $0 }.joined(separator: " · ") }
}

struct CardView: View {
    @Bindable var model: AppModel
    @State private var registrationTransport: CardTransport?
    var body: some View {
        List {
            Section {
                Label(model.usbPresent ? "USB reader reports a card" : "No USB card", systemImage: "cable.connector")
                Text("USB and Lightning connectors are supported.").font(.caption).foregroundStyle(.secondary)
            }
            Section {
                if model.registeredCards.isEmpty {
                    ContentUnavailableView("No security keys registered", systemImage: "key.horizontal", description: Text("Register once to save public information. Private keys stay on your security key."))
                }
                ForEach(model.registeredCards) { entry in
                    NavigationLink { RegisteredCardView(serial: entry.id, model: model) } label: {
                        HStack(spacing: 12) {
                            Image(systemName: "key.horizontal").font(.title2).foregroundStyle(.indigo)
                            VStack(alignment: .leading, spacing: 4) {
                                Text(verbatim: entry.name).font(.headline)
                                Text(verbatim: entry.card.serial).font(.caption.monospaced()).lineLimit(1).truncationMode(.middle)
                                Text(verbatim: entry.connections).font(.caption).foregroundStyle(.secondary)
                            }
                            Spacer()
                            if model.card?.serial == entry.id { Image(systemName: "checkmark.circle.fill").foregroundStyle(.indigo).accessibilityLabel("Selected card") }
                        }.padding(.vertical, 4)
                    }
                }
            } header: {
                Text("Registered security keys")
            } footer: {
                Text("One entry per security key. USB and NFC connections share the same public information. Only the selected key provides card services.")
            }
        }
        .navigationTitle("Security Keys")
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Menu {
                    Button { registrationTransport = .usb } label: {
                        Label("Register USB security key", systemImage: "cable.connector")
                    }
                    .accessibilityIdentifier("registerUSB")
                    Button { registrationTransport = .nfc } label: {
                        Label("Register NFC security key", systemImage: "wave.3.right")
                    }
                    .accessibilityIdentifier("registerNFC")
                } label: {
                    Label("Register security key", systemImage: "plus").labelStyle(.iconOnly)
                }
                .disabled(model.busy)
                .accessibilityIdentifier("registerSecurityKey")
            }
        }
        .navigationDestination(item: $registrationTransport) { transport in
            RegisterCardView(transport: transport, model: model)
        }
    }
}

struct RegisterCardView: View {
    let transport: CardTransport
    @Bindable var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var name = String(localized: "Security Key")
    @State private var otherSupported = true
    var body: some View {
        Form {
            Section {
                TextField("Name", text: $name)
                LabeledContent("Read using", value: transport == .usb ? String(localized: "USB") : "NFC")
                Toggle(transport == .usb ? "NFC support" : "USB connection support", isOn: $otherSupported)
            } header: { Text("Security key") } footer: {
                Text("Turn this off if your key does not support the other connection. Registration reads only the current connection; identity is checked again during use.")
            }
            Section {
                Button {
                    Task { if await model.register(transport, name: name, usbSupported: transport == .usb || otherSupported, nfcSupported: transport == .nfc || otherSupported) { dismiss() } }
                } label: {
                    HStack { Text("Read and register"); Spacer(); if model.busy { ProgressView() } }
                }.disabled(model.busy || name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || (transport == .usb && !model.usbPresent))
            } footer: {
                Text(transport == .usb ? "Insert the security key to read its public information. No PIN is required." : "Tap your security key to read its public information. No PIN is required.")
            }
        }.navigationTitle("Register security key")
    }
}

struct RegisteredCardView: View {
    let serial: String
    @Bindable var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var confirmRemoval = false
    private var entry: RegisteredCard? { model.registeredCards.first { $0.id == serial } }
    var body: some View {
        List {
            if let entry {
                Section("Security key") {
                    LabeledContent("Name", value: entry.name)
                    LabeledContent("Serial number") { Text(verbatim: serial).font(.caption.monospaced()).textSelection(.enabled) }
                    LabeledContent("Supported connections", value: entry.connections)
                    LabeledContent("Registration read using", value: entry.card.transport == .usb ? String(localized: "USB") : "NFC")
                    if model.card?.serial == serial {
                        Label("Selected card", systemImage: "checkmark.circle.fill")
                    } else {
                        Button("Use this security key") { Task { await model.selectCard(serial) } }.disabled(model.busy)
                    }
                }
                Section("OpenPGP keys") {
                    if entry.card.keys.isEmpty { Text("No keys on this card").foregroundStyle(.secondary) }
                    ForEach(entry.card.keys) { key in
                        VStack(alignment: .leading, spacing: 6) {
                            Text(key.slot == 1 ? "Signing" : (key.slot == 2 ? "Decryption" : "Authentication")).font(.headline)
                            Text(verbatim: key.algorithm).foregroundStyle(.secondary)
                            Text(verbatim: key.fingerprint).font(.caption.monospaced()).textSelection(.enabled)
                        }.padding(.vertical, 4)
                    }
                }
                Section {
                    Button("Remove registration", role: .destructive) { confirmRemoval = true }.disabled(model.busy)
                } footer: { Text("Only removes this app’s public record. It does not erase keys from the security key.") }
            }
        }
        .navigationTitle(entry?.name ?? String(localized: "Security Key"))
        .confirmationDialog("Remove registration?", isPresented: $confirmRemoval, titleVisibility: .visible) {
            Button("Remove registration", role: .destructive) {
                Task { await model.removeCard(serial); if entry == nil { dismiss() } }
            }
        }
    }
}

struct SettingsView: View {
    @Bindable var model: AppModel
    var body: some View {
        List {
            Section("This device") {
                LabeledContent("Name", value: model.device?.name ?? "")
                Text(verbatim: model.device?.id ?? "").font(.caption.monospaced()).textSelection(.enabled)
            }
            Section {
                Text(verbatim: model.device?.words ?? "").font(.system(.body, design: .monospaced)).textSelection(.enabled)
            } header: { Text("Public-key verification words") } footer: { Text("These words identify a public device key. They are not a recovery phrase.") }
            Section("Connection") {
                Text(verbatim: model.server)
                LabeledContent("Availability", value: String(localized: "While app is open"))
                LabeledContent("Protocol", value: "hibiki/2")
            }
            Section("About") { Text("HIbiki"); Text("PINs are not saved. Private keys stay on the card or the requesting computer.").foregroundStyle(.secondary) }
        }.navigationTitle("Settings")
    }
}

struct PinView: View {
    let prompt: PinPrompt
    @Bindable var model: AppModel
    @State private var pin = ""
    @State private var submitting = false
    @FocusState private var focused: Bool
    private var cardRequest: Bool { switch prompt.kind { case .cardUsb, .cardNfc: true; default: false } }
    private var asksPin: Bool { if case .pin = prompt.kind { true } else { false } }
    var body: some View {
        NavigationStack {
            Form {
                Section("Verified requester") {
                    Text(verbatim: prompt.deviceName).font(.headline)
                    Text(verbatim: prompt.channel).foregroundStyle(.secondary)
                    Text(verbatim: prompt.deviceId).font(.caption.monospaced()).textSelection(.enabled)
                }
                Section {
                    if cardRequest {
                        if prompt.kind == .cardUsb {
                            Text("Insert your security key, then continue.")
                        } else if model.selectedUSBSupported {
                            Text(model.selectedUSBAvailable ? "USB connection detected. Continue to enter the PIN." : "Connect using USB, or enter the PIN and use NFC.")
                        } else {
                            Text("Use your security key for this operation? Enter the PIN next, then tap the key.")
                        }
                        Text(verbatim: prompt.description).font(.caption.monospaced())
                    } else if !prompt.description.isEmpty { Text(verbatim: prompt.description) }
                    if !prompt.error.isEmpty { Text(verbatim: prompt.error).foregroundStyle(.red) }
                    if asksPin {
                        SecureField(prompt.label.isEmpty ? String(localized: "PIN or passphrase") : prompt.label, text: $pin).textContentType(nil).autocorrectionDisabled().textInputAutocapitalization(.never).focused($focused).accessibilityIdentifier("pinInput")
                    }
                    Button(prompt.ok.isEmpty ? String(localized: "Continue") : prompt.ok) { submit() }
                        .disabled(submitting)
                        .accessibilityIdentifier("submitPIN")
                    if !prompt.notOk.isEmpty, !asksPin { Button(prompt.notOk) { model.answer(prompt, accepted: false) } }
                }
            }
            .navigationTitle(prompt.title.isEmpty ? String(localized: "HIbiki request") : prompt.title)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button { pin = ""; model.answer(prompt, accepted: false) } label: {
                        Image(systemName: "xmark")
                    }
                    .accessibilityLabel(prompt.cancel.isEmpty ? String(localized: "Cancel") : prompt.cancel)
                    .accessibilityIdentifier("cancelPIN")
                }
            }
            .onAppear { focused = asksPin }
            .onDisappear { pin = "" }
            .privacySensitive()
        }
    }
    private func submit() {
        guard !submitting else { return }
        submitting = true
        let value = pin
        pin = ""
        Task {
            if cardRequest || asksPin { await model.refreshUSBAvailability() }
            model.answer(prompt, text: value, accepted: true)
            submitting = false
        }
    }
}
