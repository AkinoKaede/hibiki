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
                    Label("Hibiki", systemImage: "lock.shield").font(.title)
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
                Text("Use your security key and enter passphrases for GPG operations on your computers.").foregroundStyle(.secondary)
            }
            Section("Connect to your server") {
                TextField("Server URL", text: $model.server).keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled().accessibilityIdentifier("serverURL")
                TextField("Hostname", text: $model.name).accessibilityIdentifier("hostname")
            }
            Section {
                DisclosureGroup("Advanced") {
                    Toggle("Skip TLS Certificate Validation", isOn: $model.skipTLSCertificateValidation)
                }
            }
            Section {
                Button { Task { await model.setup() } } label: {
                    HStack { Text("Get started"); Spacer(); if model.busy { ProgressView() } else { Image(systemName: "arrow.right") } }
                }
                .disabled(model.busy || model.server.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || model.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                .accessibilityIdentifier("getStarted")
            } footer: { Text("Hibiki connects while the app is open. Services remain off until enabled.") }
        }.navigationTitle("Hibiki").disabled(model.busy)
    }
}

struct StatusView: View {
    @Bindable var model: AppModel
    var body: some View {
        List {
            Section {
                HStack(spacing: 16) {
                    Image(systemName: model.connection == "online" ? "checkmark.shield.fill" : "network.slash").font(.largeTitle).foregroundStyle(model.connection == "online" ? .green : .secondary)
                    VStack(alignment: .leading, spacing: 5) { Text(model.statusText).font(.title2.bold()); Text(verbatim: model.device?.name ?? "Hibiki").foregroundStyle(.secondary) }
                }.padding(.vertical, 12)
                LabeledContent("Server") { Text(verbatim: model.server).font(.caption).lineLimit(2) }
            }
            if !model.channels.contains(where: { $0.active }), model.pairing == nil {
                Section("Finish setup") {
                    Text("Join a channel in the Channels tab, then enable services for this device.")
                }
            }
            Section("Provide services") {
                Toggle("PINEntry", isOn: $model.pinEnabled).onChange(of: model.pinEnabled) { _, _ in model.updateServices() }
                Toggle("OpenPGP card", isOn: $model.cardEnabled).onChange(of: model.cardEnabled) { _, _ in model.updateServices() }
                if model.cardEnabled, model.card == nil { Text("Register your security key in the Security Keys tab.").foregroundStyle(.secondary) }
                if let card = model.card, model.cardEnabled {
                    let text = model.selectedUSBAvailable
                        ? "USB connection detected"
                        : (card.transport == .nfc
                            ? (model.selectedUSBSupported
                                ? "Connect via USB, or enter the PIN and tap with NFC."
                                : "Enter your PIN, then tap your security key with NFC.")
                            : "Confirmation required for each operation")
                    Label(
                        text,
                        systemImage: model.selectedUSBAvailable || card.transport == .usb ? "cable.connector" : "wave.3.right"
                    )
                }
            }
            if let pairing = model.pairing {
                Section("Waiting for approval") {
                    Text("Compare these verification words on a member device before approving.")
                    Text(verbatim: model.device?.words ?? "").font(.system(.body, design: .monospaced)).textSelection(.enabled)
                    LabeledContent("Request") { Text(verbatim: pairing.request).font(.caption).textSelection(.enabled) }
                    Text("This request stays pending until approved, rejected, or withdrawn.")
                    WithdrawRequestButton(model: model)
                }
            }
            Section {
                Label("Private keys remain on your security key.", systemImage: "lock.shield")
                Text("Keep Hibiki open to receive requests. Returning to the app reconnects automatically.").foregroundStyle(.secondary)
            }
        }.navigationTitle("Hibiki").refreshable { await model.refresh() }
    }
}

struct ChannelsView: View {
    @Bindable var model: AppModel
    var body: some View {
        List {
            if model.channels.isEmpty {
                ContentUnavailableView("No channels yet", systemImage: "person.2", description: Text("Join a channel using an invitation from its administrator or a trusted member."))
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
                if model.allowChannelCreation == true {
                    NavigationLink("Create a channel") { CreateChannelView(model: model) }
                } else if model.allowChannelCreation == false {
                    Text("Channel creation requires an invitation from the server administrator.").foregroundStyle(.secondary)
                } else {
                    Text("Connect to the server to check channel creation permissions.").foregroundStyle(.secondary)
                }
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
                        model.rememberPairing(try await model.client?.join(invitation: invite.trimmingCharacters(in: .whitespacesAndNewlines), psk: secret))
                        await model.refresh()
                    } }
                }.disabled(invite.isEmpty || psk.isEmpty || model.busy || model.connection != "online" || model.pairing != nil)
            } footer: { Text("Get the invitation and PSK separately from a trusted member. The invitation server must match yours.") }
            if let pairing = model.pairing {
                Section("Waiting for approval") {
                    Text(verbatim: model.device?.words ?? "").font(.system(.body, design: .monospaced)).textSelection(.enabled)
                    Text(verbatim: pairing.request).font(.caption).textSelection(.enabled)
                    Text("Compare the 24 verification words and request ID on the approving device.")
                    WithdrawRequestButton(model: model)
                }
            }
        }.navigationTitle("Join channel").onDisappear { psk = "" }
    }
}

struct WithdrawRequestButton: View {
    @Bindable var model: AppModel
    @State private var confirming = false
    var body: some View {
        Button("Withdraw request", role: .destructive) { confirming = true }
            .disabled(model.busy || model.connection != "online")
            .confirmationDialog("Withdraw this join request?", isPresented: $confirming, titleVisibility: .visible) {
                Button("Withdraw request", role: .destructive) { Task { await model.withdrawPairing() } }
            }
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
                } } }.disabled(name.isEmpty || model.busy || model.connection != "online" || model.allowChannelCreation != true)
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
            } header: { Text("Save your PSK") } footer: { Text("Store this PSK safely and share it separately from the invitation. Hibiki does not save it.") }
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
        } message: { Text("This device will not be able to rejoin this channel.") }
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
    @State private var rejected = false
    @State private var rejecting = false
    var body: some View {
        Form {
            Section("Joining device") { Text(verbatim: request.device.name); Text(verbatim: request.device.id).font(.caption.monospaced()).textSelection(.enabled) }
            Section("Public-key verification words") { Text(verbatim: request.device.words).font(.system(.body, design: .monospaced)).textSelection(.enabled) }
            Section("Request ID") { Text(verbatim: request.id).font(.caption.monospaced()).textSelection(.enabled) }
            Section {
                Toggle("I verified the 24 words and request ID", isOn: $verified)
                Button(approved ? "Approved" : "Approve device") { Task { await model.perform {
                    try await model.client?.approve(channel: request.channel, requestId: request.id)
                    approved = true; await model.refresh()
                } } }.disabled(!verified || approved || rejected || model.busy || model.connection != "online")
                Button(rejected ? "Rejected" : "Reject request", role: .destructive) { rejecting = true }
                    .disabled(approved || rejected || model.busy || model.connection != "online")
            } footer: { Text("These words verify this device’s public key. They are not a recovery phrase.") }
        }.navigationTitle("Approve device")
        .confirmationDialog("Reject this join request?", isPresented: $rejecting, titleVisibility: .visible) {
            Button("Reject request", role: .destructive) { Task { await model.perform {
                try await model.client?.rejectJoin(channel: request.channel, requestId: request.id)
                rejected = true
                await model.refresh()
            } } }
        } message: { Text("Removes this request. The device can request to join again later.") }
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
            CardInspectionView(model: model)
            Section {
                if model.registeredCards.isEmpty {
                    ContentUnavailableView(
                        "No security keys registered",
                        systemImage: "key.horizontal",
                        description: Text("Register once to save public information. Private keys always stay on your security key.")
                    )
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
                Text("USB and NFC share the same key record. Only the selected security key provides card services.")
            }
        }
        .navigationTitle("Security Keys")
        .onAppear { model.showCardInspection() }
        .onDisappear { model.cardInspection.disappear() }
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Menu {
                    Button { registrationTransport = .usb } label: {
                        Label("Register via USB", systemImage: "cable.connector")
                    }
                    .accessibilityIdentifier("registerUSB")
                    Button { registrationTransport = .nfc } label: {
                        Label("Register via NFC", systemImage: "wave.3.right")
                    }
                    .accessibilityIdentifier("registerNFC")
                } label: {
                    Label("Register security key", systemImage: "plus").labelStyle(.iconOnly)
                }
                .disabled(model.busy || model.cardInspection.isReading)
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
                Text("Turn this off if your key does not support both USB and NFC. Key identity is verified again during use.")
            }
            Section {
                Button {
                    Task { if await model.register(transport, name: name, usbSupported: transport == .usb || otherSupported, nfcSupported: transport == .nfc || otherSupported) { dismiss() } }
                } label: {
                    HStack { Text("Read and register"); Spacer(); if model.busy { ProgressView() } }
                }.disabled(model.busy || name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || (transport == .usb && !model.usbPresent))
            } footer: {
                Text(transport == .usb ? "Insert your security key to read public information. No PIN needed." : "Tap your security key to read public information. No PIN needed.")
            }
        }.navigationTitle("Register security key")
    }
}

struct RegisteredCardView: View {
    let serial: String
    @Bindable var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var confirmRemoval = false
    @State private var editing = false
    private var entry: RegisteredCard? { model.registeredCards.first { $0.id == serial } }
    var body: some View {
        List {
            if let entry {
                Section("Security key") {
                    LabeledContent("Name", value: entry.name)
                    CardIdentityFields(info: entry.card)
                    LabeledContent("Supported connections", value: entry.connections)
                    if model.card?.serial == serial {
                        Label("Selected security key", systemImage: "checkmark.circle.fill")
                    } else {
                        Button("Use this security key") { Task { await model.selectCard(serial) } }.disabled(model.busy)
                    }
                }
                Section("OpenPGP keys") {
                    CardPublicKeyRows(keys: entry.card.keys)
                }
                Section {
                    Button("Remove registration", role: .destructive) { confirmRemoval = true }.disabled(model.busy)
                } footer: { Text("Only removes this app’s saved record. It does not erase keys from your security key.") }
            }
        }
        .navigationTitle(entry?.name ?? String(localized: "Security Key"))
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button("Edit") { editing = true }.disabled(model.busy || entry == nil)
                    .accessibilityIdentifier("editSecurityKey")
            }
        }
        .sheet(isPresented: $editing) {
            if let entry { EditRegisteredCardView(entry: entry, model: model) }
        }
        .confirmationDialog("Remove registration?", isPresented: $confirmRemoval, titleVisibility: .visible) {
            Button("Remove registration", role: .destructive) {
                Task { await model.removeCard(serial); if entry == nil { dismiss() } }
            }
        }
    }
}

struct SettingsView: View {
    @Bindable var model: AppModel
    @State private var confirmDisconnect = false
    var body: some View {
        List {
            Section("This device") {
                LabeledContent("Name", value: model.device?.name ?? "")
                Text(verbatim: model.device?.id ?? "").font(.caption.monospaced()).textSelection(.enabled)
            }
            Section {
                Text(verbatim: model.device?.words ?? "").font(.system(.body, design: .monospaced)).textSelection(.enabled)
            } header: { Text("Public-key verification words") } footer: { Text("These words verify this device’s public key. They are not a recovery phrase.") }
            Section("Connection") {
                Text(verbatim: model.server)
                LabeledContent("Availability", value: String(localized: "While app is open"))
                LabeledContent("Protocol", value: "hibiki/1")
                Button("Disconnect from server", role: .destructive) { confirmDisconnect = true }
                    .disabled(model.busy).accessibilityIdentifier("disconnectServer")
            }
            Section("About") { LabeledContent("Hibiki", value: Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "—"); Text("PINs are never saved. Private keys stay on your security key or computer.").foregroundStyle(.secondary) }
        }.navigationTitle("Settings")
        .confirmationDialog("Disconnect from this server?", isPresented: $confirmDisconnect, titleVisibility: .visible) {
            Button("Disconnect", role: .destructive) { Task { await model.disconnectRelay() } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This disconnects from the server and resets local pairing. Registered security keys are kept, but you will need to pair again to reconnect.")
        }
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
                            Text(model.selectedUSBAvailable ? "USB connection detected. Continue to enter the PIN." : "Connect via USB, or enter the PIN and tap with NFC.")
                        } else {
                            Text("Use your security key for this operation? Enter your PIN, then tap the key.")
                        }
                        Text(verbatim: prompt.description).font(.caption.monospaced())
                    } else if !prompt.description.isEmpty { Text(verbatim: prompt.description) }
                    if !prompt.error.isEmpty { Text(verbatim: prompt.error).foregroundStyle(.red) }
                    if asksPin {
                        SecureField(prompt.label.isEmpty ? String(localized: "PIN or passphrase") : prompt.label, text: $pin)
                            .textContentType(nil)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .focused($focused)
                            .accessibilityIdentifier("pinInput")
                    }
                    Button(prompt.ok.isEmpty ? String(localized: "Continue") : PinentryLabel.display(prompt.ok)) { submit() }
                        .disabled(submitting)
                        .accessibilityIdentifier("submitPIN")
                    if !prompt.notOk.isEmpty, !asksPin { Button(PinentryLabel.display(prompt.notOk)) { model.answer(prompt, accepted: false) } }
                }
            }
            .navigationTitle(prompt.title.isEmpty ? String(localized: "Hibiki request") : prompt.title)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button { pin = ""; model.answer(prompt, accepted: false) } label: {
                        Image(systemName: "xmark")
                    }
                    .accessibilityLabel(prompt.cancel.isEmpty ? String(localized: "Cancel") : PinentryLabel.display(prompt.cancel))
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
