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
            if value == nil, let prompt = model.currentPrompt { model.cancelPrompt(prompt) }
        })) { prompt in
            PinView(prompt: prompt, model: model).id(prompt.token).interactiveDismissDisabled()
        }
        .alert("Unable to Complete", isPresented: Binding(get: { model.error != nil }, set: { if !$0 { model.error = nil } })) {
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
            Section("Connect to Your Server") {
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
                    HStack { Text("Get Started"); Spacer(); if model.busy { ProgressView() } else { Image(systemName: "arrow.right") } }
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
                Section("Finish Setup") {
                    Text("Join a channel in the Channels tab, then enable services for this device.")
                }
            }
            Section("Provider Services") {
                Toggle("Pinentry", isOn: $model.pinEnabled).onChange(of: model.pinEnabled) { _, _ in model.updateServices() }
                Toggle("Scdaemon", isOn: $model.cardEnabled).onChange(of: model.cardEnabled) { _, _ in model.updateServices() }
            }
            if !model.nfcCards.isEmpty {
                Section("NFC Key") { NFCKeyRows(model: model) }
            }
            if let pairing = model.pairing {
                Section("Waiting for Approval") {
                    Text("Compare these verification words on a member device before approving.")
                    VerificationWords(words: model.device?.words ?? "")
                    LabeledContent("Request") { Text(verbatim: pairing.request).font(.caption).textSelection(.enabled) }
                    Text("This request stays pending until approved, rejected, or withdrawn.")
                    WithdrawRequestButton(model: model)
                }
            }
        }.navigationTitle("Hibiki").refreshable { await model.refresh() }
    }
}

struct NFCKeyRows: View {
    @Bindable var model: AppModel
    var body: some View {
        ForEach(model.nfcCards) { entry in
            let selected = model.selectedNFCCard == entry.card.serial
            Button { model.selectNFCCard(selected ? nil : entry.card.serial) } label: {
                HStack(spacing: 10) {
                    Image(systemName: selected ? "largecircle.fill.circle" : "circle")
                    Text(verbatim: entry.name).foregroundStyle(.primary).lineLimit(1)
                    Spacer(minLength: 8)
                    Text(verbatim: formatCardNumber(serial: entry.card.serial)).font(.caption.monospaced()).foregroundStyle(.secondary)
                }
            }
            .accessibilityIdentifier("nfcCard-\(entry.card.serial)")
            .accessibilityValue(selected ? Text("Selected") : Text("Not Selected"))
        }
    }
}

struct ChannelsView: View {
    @Bindable var model: AppModel
    var body: some View {
        List {
            if model.channels.isEmpty {
                ContentUnavailableView("No Channels Yet", systemImage: "person.2", description: Text("Join a channel using an invitation from its administrator or a trusted member."))
            }
            ForEach(model.channels) { channel in
                NavigationLink { ChannelView(channelID: channel.id, model: model) } label: {
                    VStack(alignment: .leading) {
                        Text(verbatim: channel.name).font(.headline)
                        Text(channel.active ? "Member" : "Not an Active Member").font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            if model.allowChannelCreation == true {
                Section { NavigationLink("Create a Channel") { CreateChannelView(model: model) } }
            }
        }.navigationTitle("Channels").refreshable { await model.refresh() }
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    NavigationLink { JoinView(model: model) } label: {
                        Label("Join Channel", systemImage: "plus").labelStyle(.iconOnly)
                    }.accessibilityIdentifier("joinChannel")
                }
            }
    }
}

struct JoinView: View {
    @Bindable var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var submitting = false
    @State private var invite = ""
    @State private var psk = ""
    private var embeddedPSK: Bool { invite.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("hibiki-psk-v1:") }
    var body: some View {
        Form {
            Section("Invitation") { TextField("hibiki-v1:…", text: $invite, axis: .vertical).textInputAutocapitalization(.never).autocorrectionDisabled() }
            if !embeddedPSK { Section("Channel PSK") { SecureField("Pre-Shared Key", text: $psk).textInputAutocapitalization(.never).autocorrectionDisabled() } }
            Section {} footer: { Text("Get an invitation from a trusted member. Older invitations require a separate PSK. The invitation server must match yours.") }
            if let pairing = model.pairing {
                Section("Waiting for Approval") {
                    VerificationWords(words: model.device?.words ?? "")
                    Text(verbatim: pairing.request).font(.caption).textSelection(.enabled)
                    Text("Compare the 24 verification words and request ID on the approving device.")
                    WithdrawRequestButton(model: model)
                }
            }
        }
        .disabled(submitting)
        .navigationTitle("Join Channel")
        .navigationBarTitleDisplayMode(.inline)
        .navigationBarBackButtonHidden()
        .toolbar {
            ToolbarItem(placement: .topBarLeading) {
                Button { dismiss() } label: { Label("Cancel", systemImage: "xmark").labelStyle(.iconOnly) }
                    .disabled(submitting).accessibilityIdentifier("cancelJoinChannel")
            }
            ToolbarItem(placement: .topBarTrailing) {
                Button { requestToJoin() } label: { Label("Request to Join", systemImage: "checkmark").labelStyle(.iconOnly) }
                    .disabled(invite.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || (!embeddedPSK && psk.isEmpty) || submitting || model.busy || model.connection != "online" || model.pairing != nil)
                    .accessibilityIdentifier("requestToJoin")
            }
        }
        .onChange(of: embeddedPSK) { _, embedded in if embedded { psk = "" } }
        .onDisappear { psk = ""; invite = "" }
    }
    private func requestToJoin() {
        guard !submitting, !model.busy, let client = model.client else { return }
        let invitation = invite.trimmingCharacters(in: .whitespacesAndNewlines)
        let secret = embeddedPSK ? "" : psk
        psk = ""; submitting = true
        Task {
            defer { submitting = false }
            await model.perform {
                let result = try await client.join(invitation: invitation, psk: secret)
                guard model.client === client else { return }
                model.rememberPairing(result)
                await model.refresh()
                if model.pairing == nil { dismiss() }
            }
        }
    }
}

struct WithdrawRequestButton: View {
    @Bindable var model: AppModel
    @State private var confirming = false
    var body: some View {
        Button("Withdraw Request", role: .destructive) { confirming = true }
            .disabled(model.busy || model.connection != "online")
            .confirmationDialog("Withdraw this join request?", isPresented: $confirming, titleVisibility: .visible) {
                Button("Withdraw Request", role: .destructive) { Task { await model.withdrawPairing() } }
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
                Section { TextField("Channel Name", text: $name) }
                Button("Create Channel") { Task { await model.perform {
                    result = try await model.client?.createChannel(name: name)
                    await model.refresh()
                } } }.disabled(name.isEmpty || model.busy || model.connection != "online" || model.allowChannelCreation != true)
            }
        }
        .navigationTitle("Create Channel")
        .toolbar {
            if let result {
                ToolbarItem(placement: .topBarTrailing) {
                    ShareLink(item: result.invite) { Label("Share Invitation", systemImage: "square.and.arrow.up") }
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
            } header: { Text("Save Your PSK") } footer: { Text("Store this PSK safely and share it separately from the invitation. Hibiki does not save it.") }
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
    @ScaledMetric private var deviceIconWidth = 28.0
    let channelID: String
    @Bindable var model: AppModel
    @State private var pending: [PendingInfo] = []
    @State private var invitation = ""
    @State private var sharing = false
    @State private var preparedInvitation = ""
    @State private var sharePSK = ""
    @State private var psk = ""
    @State private var leaving = false
    @State private var rotating = false
    private var channel: ChannelInfo? { model.channels.first { $0.id == channelID } }
    var body: some View {
        let iconWidth = deviceIconWidth
        List {
            Section("Members") {
                ForEach(channel?.members ?? []) { device in
                    NavigationLink {
                        MemberDetailView(channelID: channelID, deviceID: device.id, model: model)
                    } label: {
                        HStack(spacing: 12) {
                            Image(systemName: device.id == model.device?.id ? "iphone" : "desktopcomputer")
                                .foregroundStyle(.secondary).frame(width: deviceIconWidth)
                            VStack(alignment: .leading, spacing: 4) {
                                Text(verbatim: device.name)
                                DeviceStatus(online: device.online, available: model.connection == "online").font(.caption)
                            }
                            Spacer()
                            if device.id == model.device?.id { Text("This Device").font(.caption).foregroundStyle(.secondary) }
                        }
                        .alignmentGuide(.listRowSeparatorLeading) { _ in iconWidth + 12 }
                    }.accessibilityIdentifier("member-\(device.id)")
                }
            }
            if channel?.active == true {
                Section("Pending Requests") {
                    if pending.isEmpty { Text("No Pending Requests").foregroundStyle(.secondary) }
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
                            sharing = true
                        } label: { Label("Invite Device", systemImage: "square.and.arrow.up") }
                        .accessibilityIdentifier("inviteDevice")
                        Button { rotating = true } label: { Label("Rotate PSK", systemImage: "arrow.triangle.2.circlepath") }
                        Divider()
                        Button(role: .destructive) { leaving = true } label: {
                            Label {
                                Text("Leave Channel")
                            } icon: {
                                if let icon = UIImage(systemName: "rectangle.portrait.and.arrow.right") {
                                    Image(uiImage: icon.withTintColor(.systemRed, renderingMode: .alwaysOriginal))
                                        .renderingMode(.original)
                                }
                            }
                        }
                    } label: { Label("Channel Actions", systemImage: "ellipsis") }
                    .disabled(model.connection != "online" || model.busy)
                    .accessibilityIdentifier("channelActions")
                }
            }
        }
        .sheet(isPresented: $sharing, onDismiss: { sharePSK = ""; invitation = preparedInvitation; preparedInvitation = "" }) {
            NavigationStack {
                Form {
                    SecureField("Channel PSK", text: $sharePSK).textInputAutocapitalization(.never).autocorrectionDisabled()
                    Button("Generate Invitation") {
                        let secret = sharePSK; sharePSK = ""
                        Task { await model.perform {
                            preparedInvitation = try await model.client?.invitationWithPsk(channel: channelID, psk: secret) ?? ""
                            sharing = false
                        } }
                    }.disabled(sharePSK.isEmpty || model.busy)
                }.navigationTitle("Invite Device")
                    .toolbar {
                        ToolbarItem(placement: .cancellationAction) {
                            Button { sharing = false } label: { Label("Cancel", systemImage: "xmark").labelStyle(.iconOnly) }
                                .disabled(model.busy).accessibilityIdentifier("cancelInviteDevice")
                        }
                    }
                    .interactiveDismissDisabled(model.busy)
            }
        }
        .sheet(isPresented: Binding(get: { !invitation.isEmpty }, set: { if !$0 { invitation = "" } })) {
            InvitationShareSheet(invitation: invitation)
                .presentationDetents([.medium, .large])
        }
        .task { await load() }.refreshable { await load() }
        .confirmationDialog("Leave this channel?", isPresented: $leaving, titleVisibility: .visible) {
            Button("Leave Channel", role: .destructive) { Task { await model.perform { try await model.client?.leave(channel: channelID); await load() } } }
        }
        .confirmationDialog("Rotate channel PSK?", isPresented: $rotating, titleVisibility: .visible) {
            Button("Rotate PSK") { Task { await model.perform { psk = try await model.client?.rotatePsk(channel: channelID) ?? ""; await load() } } }
        } message: { Text("Pending requests will be invalidated. Approved members retain access.") }
        .onDisappear { psk = ""; sharePSK = ""; invitation = ""; preparedInvitation = "" }
    }
    private func load() async {
        await model.refresh()
        if channel?.active == true { do { pending = try await model.client?.pending(channel: channelID) ?? [] } catch { model.show(error) } }
    }
}

struct MemberDetailView: View {
    let channelID: String
    let deviceID: String
    @Bindable var model: AppModel
    @State private var revoking = false
    @State private var revokeSubtree = false
    @State private var revokeRevision: UInt64 = 0
    @State private var revokeDevices: [DeviceInfo] = []
    @State private var ping = DevicePing()
    private var channel: ChannelInfo? { model.channels.first { $0.id == channelID } }
    private var device: DeviceInfo? { channel?.members.first { $0.id == deviceID } }
    private var isSelf: Bool { deviceID == model.device?.id }
    private var online: Bool { model.connection == "online" }
    private var canManage: Bool { online && channel?.active == true && device != nil && !model.busy }
    private var canPing: Bool { canManage && !isSelf && device?.online == true && device?.revokedByServer == false && model.foreground }

    var body: some View {
        Form {
            if let device {
                Section("Device") {
                    LabeledContent("Name") { Text(verbatim: device.name).textSelection(.enabled) }
                    HStack {
                        Text("Status")
                        Spacer()
                        DeviceStatus(online: device.online, available: online)
                    }.accessibilityIdentifier("memberStatus")
                    if isSelf { Label("This Device", systemImage: "iphone") }
                    if device.revokedByServer { Label("Revoked by Server", systemImage: "lock.slash").foregroundStyle(.red) }
                    if let approver = device.approvedBy {
                        LabeledContent("Approved by") { Text(verbatim: device.approverName ?? approver) }
                        Text(verbatim: approver).font(.caption.monospaced()).textSelection(.enabled)
                    } else {
                        LabeledContent("Approval Role", value: String(localized: "Channel Founder"))
                    }
                    LabeledContent("Channel") { Text(verbatim: channel?.name ?? channelID) }
                }
                if !isSelf {
                    DevicePingSection(ping: ping, canPing: canPing) { startPing() }
                }
                Section("Device ID") {
                    Text(verbatim: device.id).font(.caption.monospaced()).textSelection(.enabled)
                    Button { UIPasteboard.general.string = device.id } label: { Label("Copy Device ID", systemImage: "doc.on.doc") }
                }
                Section {
                    VerificationWords(words: device.words)
                } header: { Text("Public-Key Verification Words") } footer: {
                    Text("These words verify this device’s public key. They are not a recovery phrase.")
                }
                if !isSelf {
                    Section {
                        if device.canRevoke {
                            Button("Revoke Device", role: .destructive) { prepareRevocation(subtree: false) }.disabled(!canManage)
                            if !device.revocationSubtree.isEmpty {
                                Button("Revoke Entire Approval Subtree", role: .destructive) { prepareRevocation(subtree: true) }.disabled(!canManage)
                            }
                        } else if device.revokedByServer {
                            Label("Revoked by Server", systemImage: "lock.slash")
                        } else if let availableAt = device.reverseRevokeAvailableAt {
                            LabeledContent("Ancestor Revocation Available") { Text(Date(timeIntervalSince1970: TimeInterval(availableAt)), style: .date) }
                        } else {
                            Label("Outside Your Approval Branch", systemImage: "lock.shield")
                        }
                    } footer: { Text("You can revoke devices below you in the approval chain. After 30 days of your current membership, you can also revoke your approver or ancestors. Subtree removal is optional and applies only to descendants.") }
                }
            } else {
                ContentUnavailableView("Device No Longer Available", systemImage: "person.crop.circle.badge.minus", description: Text("The device is no longer a member of this channel."))
                Section("Device ID") { Text(verbatim: deviceID).font(.caption.monospaced()).textSelection(.enabled) }
            }
        }
        .navigationTitle(device?.name ?? String(localized: "Device"))
        .navigationBarTitleDisplayMode(.inline)
        .refreshable { await model.refresh() }
        .sheet(isPresented: $revoking) {
            NavigationStack {
                List {
                    Section {
                        Text(revokeSubtree ? "Revoke Entire Approval Subtree" : "Revoke Device")
                        Text("Affected devices: \(revokeDevices.count)")
                        Text("These identities will lose access and cannot rejoin this channel.")
                    }
                    ForEach(revokeDevices, id: \.id) { affected in
                        Section {
                            Text(verbatim: affected.name)
                            Text(verbatim: affected.id).font(.caption.monospaced()).textSelection(.enabled)
                        }
                    }
                    Section {
                        Button("Confirm Revocation", role: .destructive) {
                            revoking = false
                            Task { await model.perform {
                                guard canManage, device?.canRevoke == true else { return }
                                try await model.client?.revokeSelected(channel: channelID, device: deviceID, subtree: revokeSubtree, revision: revokeRevision)
                                await model.refresh()
                            } }
                        }.disabled(!canManage || channel?.revision != revokeRevision)
                    }
                }
                .navigationTitle("Review Revocation")
                .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel", role: .cancel) { revoking = false }.keyboardShortcut(.cancelAction) } }
            }
        }
        .onChange(of: channel?.revision) { _, revision in if revision != revokeRevision { revoking = false } }
        .onChange(of: canPing) { _, available in if !available { ping.stop() } }
        .onChange(of: device?.canRevoke) { _, allowed in if allowed != true { revoking = false } }
        .onChange(of: canManage) { _, available in if !available { revoking = false } }
        .onDisappear { ping.stop() }
    }
    private func prepareRevocation(subtree: Bool) {
        guard let channel, let device, canManage, device.canRevoke else { return }
        revokeSubtree = subtree
        revokeRevision = channel.revision
        revokeDevices = channel.members.filter { subtree ? device.revocationSubtree.contains($0.id) : $0.id == deviceID }
        revoking = !revokeDevices.isEmpty
    }
    private func startPing() {
        guard canPing, let client = model.client else { return }
        ping.start { cancellation in
            try await client.pingDevice(channel: channelID, device: deviceID, count: 1, cancellation: cancellation)
        }
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
            Section("Joining Device") { Text(verbatim: request.device.name); Text(verbatim: request.device.id).font(.caption.monospaced()).textSelection(.enabled) }
            Section("Public-Key Verification Words") { VerificationWords(words: request.device.words) }
            Section("Request ID") { Text(verbatim: request.id).font(.caption.monospaced()).textSelection(.enabled) }
            Section {
                Toggle("I verified the 24 words and request ID", isOn: $verified)
                Button(approved ? "Approved" : "Approve Device") { Task { await model.perform {
                    try await model.client?.approve(channel: request.channel, requestId: request.id)
                    approved = true; await model.refresh()
                } } }.disabled(!verified || approved || rejected || model.busy || model.connection != "online")
                Button(rejected ? "Rejected" : "Reject Request", role: .destructive) { rejecting = true }
                    .disabled(approved || rejected || model.busy || model.connection != "online")
            } footer: { Text("These words verify this device’s public key. They are not a recovery phrase.") }
        }.navigationTitle("Approve Device")
        .confirmationDialog("Reject this join request?", isPresented: $rejecting, titleVisibility: .visible) {
            Button("Reject Request", role: .destructive) { Task { await model.perform {
                try await model.client?.rejectJoin(channel: request.channel, requestId: request.id)
                rejected = true
                await model.refresh()
            } } }
        } message: { Text("Removes this request. The device can request to join again later.") }
    }
}

extension RegisteredCard: Identifiable {
    public var id: String { card.serial }
}

struct CardView: View {
    @Bindable var model: AppModel
    @State private var registering = false
    var body: some View {
        List {
            CardInspectionView(model: model)
            Section {
                if model.registeredCards.isEmpty {
                    ContentUnavailableView(
                        "No NFC Keys Registered",
                        systemImage: "key.horizontal",
                        description: Text("Register NFC keys to use them without a USB connection.")
                    )
                }
                ForEach(model.registeredCards) { entry in
                    NavigationLink { RegisteredCardView(serial: entry.id, model: model) } label: {
                        HStack(spacing: 12) {
                            Image(systemName: "key.horizontal").font(.title2).foregroundStyle(.indigo)
                            VStack(alignment: .leading, spacing: 4) {
                                Text(verbatim: entry.name).font(.headline)
                                Text(verbatim: entry.card.serial).font(.caption.monospaced()).lineLimit(1).truncationMode(.middle)
                            }
                            Spacer()
                        }.padding(.vertical, 4)
                    }
                }
            } header: {
                Text("Registered NFC Keys")
            }
        }
        .navigationTitle("Security Keys")
        .onAppear { model.showCardInspection() }
        .onDisappear { model.cardInspection.disappear() }
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                if model.nfcAvailable {
                    Button { registering = true } label: {
                        Label("Register NFC Key", systemImage: "plus").labelStyle(.iconOnly)
                    }
                    .disabled(model.busy || model.cardInspection.isReading)
                    .accessibilityIdentifier("registerSecurityKey")
                }
            }
        }
        .navigationDestination(isPresented: $registering) {
            RegisterCardView(model: model)
        }
    }
}

struct RegisterCardView: View {
    @Bindable var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    var body: some View {
        Form {
            Section("NFC Security Key") {
                TextField("Name (read from card if blank)", text: $name)
            }
            Section {
                Button {
                    Task { if await model.register(name: name) { dismiss() } }
                } label: {
                    HStack { Text("Read and Register"); Spacer(); if model.busy { ProgressView() } }
                }.disabled(model.busy || !model.nfcAvailable)
            } footer: {
                Text("Tap your security key to read public information. No PIN needed.")
            }
        }.navigationTitle("Register NFC Key")
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
                Section("Security Key") {
                    LabeledContent("Name", value: entry.name)
                    CardIdentityFields(info: entry.card)
                }
                Section("OpenPGP Keys") {
                    CardPublicKeyRows(keys: entry.card.keys)
                }
                Section {
                    Button("Remove Registration", role: .destructive) { confirmRemoval = true }.disabled(model.busy)
                } footer: { Text("Only removes this app’s saved record. It does not erase keys from your security key.") }
            }
        }
        .navigationTitle(entry?.name ?? String(localized: "Security Key"))
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button { editing = true } label: { Label("Edit", systemImage: "pencil").labelStyle(.iconOnly) }.disabled(model.busy || entry == nil)
                    .accessibilityIdentifier("editSecurityKey")
            }
        }
        .sheet(isPresented: $editing) {
            if let entry { EditRegisteredCardView(entry: entry, model: model) }
        }
        .confirmationDialog("Remove registration?", isPresented: $confirmRemoval, titleVisibility: .visible) {
            Button("Remove Registration", role: .destructive) {
                Task { await model.removeCard(serial); if entry == nil { dismiss() } }
            }
        }
    }
}

struct SettingsView: View {
    @Bindable var model: AppModel
    @State private var confirmDisconnect = false
    @State private var renaming = false
    @State private var newName = ""
    var body: some View {
        List {
            Section("This Device") {
                LabeledContent("Name", value: model.device?.name ?? "")
                Button("Rename Device") { newName = model.device?.name ?? ""; renaming = true }.disabled(model.busy || model.connection != "online")
                Text(verbatim: model.device?.id ?? "").font(.caption.monospaced()).textSelection(.enabled)
            }
            Section {
                VerificationWords(words: model.device?.words ?? "")
            } header: { Text("Public-Key Verification Words") } footer: { Text("These words verify this device’s public key. They are not a recovery phrase.") }
            Section("Connection") {
                Text(verbatim: model.server)
                LabeledContent("Protocol", value: "hibiki/2")
                Button("Disconnect", role: .destructive) { confirmDisconnect = true }
                    .disabled(model.busy).accessibilityIdentifier("disconnectServer")
            }
            Section("About") { LabeledContent("Hibiki", value: Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "—") }
        }.navigationTitle("Settings")
        .alert("Rename This Device", isPresented: $renaming) {
            TextField("Device Name", text: $newName)
            Button("Cancel", role: .cancel) {}
            Button("Save") { Task { await model.renameDevice(newName) } }
        } message: { Text("Keys, device ID and verification words stay unchanged.") }
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
                Section("Verified Requester") {
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Text(verbatim: prompt.deviceName).font(.headline)
                            Spacer()
                            Text(verbatim: prompt.channel).font(.subheadline).foregroundStyle(.secondary)
                        }
                        Text(verbatim: prompt.deviceId).font(.caption2.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
                    }
                }
                Section {
                    if cardRequest {
                        if prompt.kind == .cardUsb {
                            Text("Insert your security key, then continue.")
                        } else if model.nfcAvailable {
                            Text("Use your security key for this operation? Enter your PIN, then tap the key.")
                        } else {
                            Text("Insert your security key, then continue.")
                        }
                        Text(verbatim: prompt.description).font(.caption.monospaced())
                    } else if !prompt.description.isEmpty { Text(verbatim: prompt.description) }
                    if !prompt.error.isEmpty { Text(verbatim: prompt.error).foregroundStyle(.red) }
                    if asksPin {
                        SecureField(prompt.label.isEmpty ? String(localized: "PIN or Passphrase") : prompt.label, text: $pin)
                            .textContentType(nil)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .focused($focused)
                            .accessibilityIdentifier("pinInput")
                    }
                    if prompt.kind == .confirm { NFCKeyRows(model: model) }
                    Button(prompt.ok.isEmpty ? String(localized: "Continue") : PinentryLabel.display(prompt.ok)) { submit() }
                        .disabled(submitting || (prompt.kind == .cardUsb && !model.usbPresent))
                        .accessibilityIdentifier("submitPIN")
                    if !prompt.notOk.isEmpty, !asksPin { Button(PinentryLabel.display(prompt.notOk)) { model.answer(prompt, accepted: false) } }
                }
            }
            .listSectionSpacing(.compact)
            .navigationTitle(prompt.title.isEmpty ? String(localized: "Hibiki Request") : prompt.title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button { pin = ""; model.cancelPrompt(prompt) } label: {
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
