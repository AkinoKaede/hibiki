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
                TabView(selection: $model.selectedTab) {
                    NavigationStack { StatusView(model: model) }.tabItem { Label("Status", systemImage: "waveform") }.tag("status")
                    NavigationStack(path: $model.channelPath) {
                        ChannelsView(model: model)
                            .navigationDestination(for: ChannelRoute.self) { route in
                                switch route {
                                case .channel(let id): ChannelView(channelID: id, model: model)
                                case .approval(let channel, let id):
                                    if let request = model.pendingJoins[channel]?.first(where: { $0.id == id }) {
                                        ApprovalView(request: request, model: model)
                                    } else {
                                        ContentUnavailableView("Request Unavailable", systemImage: "clock.badge.xmark", description: Text("This request is no longer pending."))
                                    }
                                }
                            }
                    }.tabItem { Label("Channels", systemImage: "person.2") }.tag("channels")
                    NavigationStack { CardView(model: model) }.tabItem { Label("Security Keys", systemImage: "key.horizontal") }.tag("cards")
                    NavigationStack { SettingsView(model: model) }.tabItem { Label("Settings", systemImage: "gearshape") }.tag("settings")
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
        // Buttons explicitly answer/cancel. A lifecycle-driven dismissal must not cancel.
        .sheet(item: Binding(get: { model.currentPrompt }, set: { _ in })) { prompt in
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
            if case .operation = model.unavailableNotification {
                UnavailableNotificationSection(model: model)
            }
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
                Toggle("Scdaemon", isOn: $model.cardEnabled).onChange(of: model.cardEnabled) { _, _ in model.updateServices() }
                Toggle("Pinentry", isOn: $model.pinEnabled).onChange(of: model.pinEnabled) { _, _ in model.updateServices() }
            }
            if model.nfcAvailable {
                Section { NFCRecordRows(model: model) } header: { Text("NFC Key") } footer: {
                    Text("The current key is remembered only until the app closes. No PIN needed to read it.")
                }
            }
            if let pairing = model.pairing {
                PendingJoinSection(pairing: pairing, model: model)
            }
        }.navigationTitle("Hibiki").refreshable { await model.refresh() }
    }
}

struct UnavailableNotificationSection: View {
    @Bindable var model: AppModel
    var body: some View {
        Section("Request Unavailable") {
            Label("This request is no longer pending.", systemImage: "clock.badge.xmark")
            Button("OK") { model.unavailableNotification = nil }
                .accessibilityIdentifier("dismissUnavailableNotice")
        }
    }
}

struct NFCRecordRows: View {
    @Bindable var model: AppModel
    var body: some View {
        if let card = model.recordedNFCCard {
            LabeledContent("Current NFC Key", value: formatCardNumber(serial: card.serial))
        }
        Button(model.recordedNFCCard == nil ? "Use NFC Key" : "Rescan NFC Key") {
            Task { await model.recordNFCCard() }
        }
        .disabled(model.busy || model.cardInspection.isReading)
        .accessibilityIdentifier("recordNFCKey")
        if model.recordedNFCCard != nil {
            Button("Forget NFC Key", role: .destructive) { model.clearNFCRecord() }
                .disabled(model.busy)
                .accessibilityIdentifier("forgetNFCKey")
        }
    }
}

struct ChannelsView: View {
    @Bindable var model: AppModel
    var body: some View {
        List {
            if model.channels.isEmpty, model.pairing == nil {
                ContentUnavailableView("No Channels Yet", systemImage: "person.2", description: Text(model.allowChannelCreation == true ? "Create a channel or join one using an invitation." : "Join a channel using an invitation from its administrator or a trusted member."))
            }
            ForEach(model.channels) { channel in
                NavigationLink { ChannelView(channelID: channel.id, model: model) } label: {
                    VStack(alignment: .leading) {
                        Text(verbatim: channel.name).font(.headline)
                        Text(channel.active ? "Member" : (model.pairing?.channel == channel.id ? "Waiting for Approval" : "Not an Active Member")).font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            if let pairing = model.pairing, !model.channels.contains(where: { $0.id == pairing.channel }) {
                NavigationLink { ChannelView(channelID: pairing.channel, model: model) } label: {
                    Label("Waiting for Approval", systemImage: "hourglass")
                }
            }
        }.navigationTitle("Channels").refreshable { await model.refresh() }
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    if model.allowChannelCreation == true {
                        Menu {
                            NavigationLink { CreateChannelView(model: model) } label: {
                                Label("Create Channel", systemImage: "plus.circle")
                            }.accessibilityIdentifier("createChannel")
                            NavigationLink { JoinView(model: model) } label: {
                                Label("Join Channel", systemImage: "arrow.right.circle")
                            }.accessibilityIdentifier("joinChannel")
                        } label: {
                            Label("Add Channel", systemImage: "plus").labelStyle(.iconOnly)
                        }.accessibilityIdentifier("addChannel")
                    } else {
                        NavigationLink { JoinView(model: model) } label: {
                            Label("Join Channel", systemImage: "plus").labelStyle(.iconOnly)
                        }.accessibilityIdentifier("joinChannel")
                    }
                }
            }
    }
}

struct JoinView: View {
    @Bindable var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var submitting = false
    @State private var invite = ""
    @State private var scanning = false
    @State private var preview: InvitationPreview?
    @State private var invitationError: String?
    var body: some View {
        Form {
            if let pairing = model.pairing {
                PendingJoinSection(pairing: pairing, model: model)
            } else {
                Section("Invitation") { TextField("hibiki-invite-v2:…", text: $invite, axis: .vertical).textInputAutocapitalization(.never).autocorrectionDisabled() }
                Section { Button { scanning = true } label: { Label("Scan Invitation", systemImage: "qrcode.viewfinder") }.accessibilityIdentifier("scanInvitation") }
                if let invitationError { Text(verbatim: invitationError).foregroundStyle(.red) }
                if let preview {
                    Section("Invitation Details") {
                        Text(verbatim: preview.name)
                        Text(verbatim: preview.server).font(.caption)
                        Text(Date(timeIntervalSince1970: TimeInterval(preview.expiresAt)), style: .relative)
                    }
                }
                Section {} footer: { Text("Get a one-use invitation from a trusted member. It expires after 24 hours. The invitation server must match yours.") }
            }
        }
        .disabled(submitting)
        .navigationTitle("Join Channel")
        .navigationBarTitleDisplayMode(.inline)
        .navigationBarBackButtonHidden()
        .toolbar {
            ToolbarItem(placement: .topBarLeading) {
                Button { dismiss() } label: {
                    Label(model.pairing == nil ? "Cancel" : "Done", systemImage: model.pairing == nil ? "xmark" : "checkmark").labelStyle(.iconOnly)
                }
                    .disabled(submitting).accessibilityIdentifier("cancelJoinChannel")
            }
            if model.pairing == nil {
                ToolbarItem(placement: .topBarTrailing) {
                    Button { requestToJoin() } label: { Label("Request to Join", systemImage: "checkmark").labelStyle(.iconOnly) }
                        .disabled(invite.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || preview == nil || submitting || model.busy || model.connection != "online")
                        .accessibilityIdentifier("requestToJoin")
                }
            }
        }
        .onChange(of: invite) { _, value in
            preview = nil; invitationError = nil
            guard !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return }
            do { preview = try model.client?.invitationPreview(text: value.trimmingCharacters(in: .whitespacesAndNewlines)) }
            catch { invitationError = pairingError(error) }
        }
        .sheet(isPresented: $scanning) {
            QRScannerSheet(purpose: .invitation, describeError: pairingError) { value in
                guard let client = model.client else { throw CancellationError() }
                let parsed = try client.invitationPreview(text: value)
                try Task.checkCancellation()
                invite = value; preview = parsed
            }
        }
        .onDisappear { invite = ""; preview = nil; scanning = false }
    }
    private func requestToJoin() {
        guard !submitting, !model.busy, let client = model.client else { return }
        let invitation = invite.trimmingCharacters(in: .whitespacesAndNewlines)
        submitting = true
        Task {
            defer { submitting = false }
            await model.perform {
                let result = try await client.join(invitation: invitation)
                guard model.client === client else { return }
                model.rememberPairing(result)
                await model.refresh()
                if model.pairing == nil { dismiss() }
            }
        }
    }
}

struct PendingJoinSection: View {
    let pairing: JoinInfo
    @Bindable var model: AppModel
    var body: some View {
        Section("Waiting for Approval") {
            Text("Compare the 24 verification words and request ID on the approving device.")
            if !pairing.verification.isEmpty { PairingQRCode(text: pairing.verification) }
            VerificationWords(words: model.device?.words ?? "")
            LabeledContent("Request ID") { Text(verbatim: pairing.request).font(.caption.monospaced()).textSelection(.enabled) }
            Text("This request stays pending until approved, rejected, or withdrawn.")
            WithdrawRequestButton(model: model)
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
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var result: Invitation?
    @State private var submitting = false
    private var channelName: String { name.trimmingCharacters(in: .whitespacesAndNewlines) }
    var body: some View {
        Group {
            if let result {
                InvitationView(invitation: result)
            } else {
                Form {
                    Section { TextField("Channel Name", text: $name).accessibilityIdentifier("channelName") }
                    if model.connection != "online" {
                        Section {} footer: { Text("Connect to the server to create a channel.") }
                    } else if model.allowChannelCreation == false {
                        Section {} footer: { Text("This server does not allow channel creation. Ask an administrator for an invitation.") }
                    } else if model.allowChannelCreation == nil {
                        ProgressView()
                    }
                }
                .disabled(submitting)
                .navigationTitle("Create Channel")
                .toolbar {
                    ToolbarItem(placement: .topBarLeading) {
                        Button { dismiss() } label: { Label("Cancel", systemImage: "xmark").labelStyle(.iconOnly) }
                            .disabled(submitting).accessibilityIdentifier("cancelCreateChannel")
                    }
                    ToolbarItem(placement: .topBarTrailing) {
                        Button { create() } label: { Label("Create Channel", systemImage: "checkmark").labelStyle(.iconOnly) }
                            .disabled(channelName.isEmpty || submitting || model.busy || model.connection != "online" || model.allowChannelCreation != true)
                            .accessibilityIdentifier("submitCreateChannel")
                    }
                }
            }
        }
        .navigationBarTitleDisplayMode(.inline)
        .navigationBarBackButtonHidden()
    }
    private func create() {
        guard !submitting, !model.busy, model.connection == "online", model.allowChannelCreation == true,
              !channelName.isEmpty, let client = model.client else { return }
        let name = channelName
        submitting = true
        Task {
            defer { submitting = false }
            await model.perform {
                let invitation = try await client.createChannel(name: name)
                guard model.client === client else { return }
                result = invitation
                await model.refresh()
            }
        }
    }
}

/// Own the activity sheet above the form so presentation cannot remove its source row.
struct InvitationView: View {
    let invitation: Invitation?
    @Environment(\.dismiss) private var dismiss
    @State private var sharing = false
    var body: some View {
        Form {
            if let invitation {
                InvitationSections(invite: invitation.invite, expiresAt: invitation.expiresAt)
            } else { ProgressView() }
        }
        .navigationTitle("Invite Device")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarLeading) {
                Button { dismiss() } label: { Label("Done", systemImage: "checkmark").labelStyle(.iconOnly) }
                    .accessibilityIdentifier("cancelInviteDevice")
            }
            ToolbarItem(placement: .topBarTrailing) {
                Button { sharing = true } label: { Label("Share Invitation", systemImage: "square.and.arrow.up").labelStyle(.iconOnly) }
                    .disabled(invitation == nil).accessibilityIdentifier("shareInvitation")
            }
        }
        .sheet(isPresented: $sharing) {
            if let invitation { QRShareSheet(text: invitation.invite) }
        }
    }
}

struct InvitationSections: View {
    let invite: String
    let expiresAt: UInt64
    var body: some View {
        Section {
            PairingQRCode(text: invite).privacySensitive()
            Text(verbatim: invite).font(.caption.monospaced()).lineLimit(3).textSelection(.enabled).privacySensitive()
            LabeledContent("Expires") { Text(Date(timeIntervalSince1970: TimeInterval(expiresAt)), style: .relative) }
            Button("Copy Invitation") { UIPasteboard.general.setItems([[UIPasteboard.typeAutomatic: invite]], options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(120)]) }
        } header: { Text("Invitation") } footer: { Text("This invitation can be used once. A submitted request still needs approval.") }
    }
}

struct ChannelView: View {
    @ScaledMetric private var deviceIconWidth = 28.0
    let channelID: String
    @Bindable var model: AppModel
    private var pending: [PendingInfo] { model.pendingJoins[channelID] ?? [] }
    @State private var invitation: Invitation?
    @State private var sharing = false
    @State private var leaving = false
    private var channel: ChannelInfo? { model.channels.first { $0.id == channelID } }
    private var pairing: JoinInfo? {
        guard channel?.active != true, model.pairing?.channel == channelID else { return nil }
        return model.pairing
    }
    var body: some View {
        let iconWidth = deviceIconWidth
        List {
            if case .join(let channel, _) = model.unavailableNotification, channel == channelID {
                UnavailableNotificationSection(model: model)
            }
            if let pairing {
                PendingJoinSection(pairing: pairing, model: model)
            } else if channel?.active != true {
                ContentUnavailableView("Not an Active Member", systemImage: "person.crop.circle.badge.exclamationmark", description: Text("Join this channel with a new invitation."))
            } else {
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
            }
            Section("Channel ID") { Text(verbatim: channelID).font(.caption.monospaced()).textSelection(.enabled) }
        }
        .navigationTitle(channel?.name ?? String(localized: "Channel"))
        .toolbar {
            if channel?.active == true {
                ToolbarItem(placement: .topBarTrailing) {
                    Menu {
                        Button {
                            sharing = true
                            Task { await model.perform {
                                let value = try await model.client?.invitation(channel: channelID)
                                if sharing { invitation = value }
                            } }
                        } label: { Label("Invite Device", systemImage: "square.and.arrow.up") }
                        .accessibilityIdentifier("inviteDevice")
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
        .sheet(isPresented: $sharing, onDismiss: { invitation = nil }) {
            NavigationStack {
                InvitationView(invitation: invitation)
            }
        }
        .task { await load() }.refreshable { await load() }
        .confirmationDialog("Leave this channel?", isPresented: $leaving, titleVisibility: .visible) {
            Button("Leave Channel", role: .destructive) { Task { await model.perform { try await model.client?.leave(channel: channelID); await load() } } }
        }
    }
    private func load() async {
        await model.refresh()
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
                            Button("Revoke", role: .destructive) { prepareRevocation(subtree: false) }.disabled(!canManage)
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
                        Text(revokeSubtree ? "Revoke Entire Approval Subtree" : "Revoke")
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
    @State private var scanning = false
    var body: some View {
        Form {
            Section("Joining Device") { Text(verbatim: request.device.name); Text(verbatim: request.device.id).font(.caption.monospaced()).textSelection(.enabled) }
            Section("Public-Key Verification Words") { VerificationWords(words: request.device.words) }
            Section("Request ID") { Text(verbatim: request.id).font(.caption.monospaced()).textSelection(.enabled) }
            Section {
                Button { scanning = true } label: { Label("Scan and Approve", systemImage: "qrcode.viewfinder") }
                    .disabled(approved || rejected || model.busy || model.connection != "online")
                    .accessibilityIdentifier("scanAndApprove")
                Toggle("I verified the 24 words and request ID", isOn: $verified)
                Button(approved ? "Approved" : "Approve") { Task { await model.perform {
                    try await model.client?.approve(channel: request.channel, requestId: request.id)
                    approved = true; await model.refresh()
                } } }.disabled(!verified || approved || rejected || model.busy || model.connection != "online")
                Button(rejected ? "Rejected" : "Reject", role: .destructive) { rejecting = true }
                    .disabled(approved || rejected || model.busy || model.connection != "online")
            } footer: { Text("These words verify this device’s public key. They are not a recovery phrase.") }
        }.navigationTitle("Approve")
        .sheet(isPresented: $scanning) {
            QRScannerSheet(purpose: .verification, describeError: pairingError) { code in
                guard !approved, !rejected, !model.busy, model.foreground, let client = model.client else { throw CancellationError() }
                model.busy = true; defer { model.busy = false }
                try Task.checkCancellation()
                let cancellation = PairingCancellation()
                try await withTaskCancellationHandler {
                    try await client.approveVerification(channel: request.channel, requestId: request.id, code: code, cancellation: cancellation)
                } onCancel: { cancellation.cancel() }
                approved = true
                await model.refresh()
            }
        }
        .onDisappear { scanning = false }
        .confirmationDialog("Reject this join request?", isPresented: $rejecting, titleVisibility: .visible) {
            Button("Reject", role: .destructive) { Task { await model.perform {
                try await model.client?.rejectJoin(channel: request.channel, requestId: request.id)
                rejected = true
                await model.refresh()
            } } }
        } message: { Text("Removes this request. The device can request to join again later.") }
    }
}

struct CardView: View {
    @Bindable var model: AppModel
    var body: some View {
        List { CardInspectionView(model: model) }
            .navigationTitle("Security Keys")
            .onAppear { model.showCardInspection() }
            .onDisappear { model.cardInspection.disappear() }
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
                LabeledContent("Protocol", value: "hibiki/4")
                Button("Disconnect", role: .destructive) { confirmDisconnect = true }
                    .disabled(model.busy).accessibilityIdentifier("disconnectServer")
            }
            Section {
                LabeledContent("Notifications", value: model.notificationAuthorization.label)
                Button("Open Notification Settings") {
                    if let url = URL(string: UIApplication.openNotificationSettingsURLString) { UIApplication.shared.open(url) }
                }
            } header: { Text("Background Requests") } footer: {
                Text("Hibiki keeps the connection while iOS allows background execution. Notifications require permission and cannot arrive after the app is suspended.")
            }
            Section("About") { LabeledContent("Hibiki", value: Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "—") }
        }.navigationTitle("Settings")
        .task { await model.refreshNotificationAuthorization() }
        .alert("Rename This Device", isPresented: $renaming) {
            TextField("Device Name", text: $newName)
            Button("Cancel", role: .cancel) {}
            Button("Save") { Task { await model.renameDevice(newName) } }
        } message: { Text("Keys, device ID and verification words stay unchanged.") }
        .confirmationDialog("Disconnect from this server?", isPresented: $confirmDisconnect, titleVisibility: .visible) {
            Button("Disconnect", role: .destructive) { Task { await model.disconnectRelay() } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This disconnects from the server, resets local pairing, and forgets the current NFC key. You will need to pair again to reconnect.")
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
    private var insertionConfirmation: Bool {
        model.nfcAvailable && prompt.kind == .confirm && cardInsertionNumber(description: prompt.description) != nil
    }
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
                    if insertionConfirmation && model.nfcAvailable {
                        Text("Continue with USB, or tap your key with NFC if no USB key is connected.")
                            .font(.caption).foregroundStyle(.secondary)
                            .accessibilityIdentifier("insertionNFCHint")
                    }
                    Button(prompt.ok.isEmpty ? String(localized: "Continue") : PinentryLabel.display(prompt.ok)) { submit() }
                        .disabled(submitting || (insertionConfirmation && model.busy) || (prompt.kind == .cardUsb && !model.usbPresent))
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
            .onChange(of: model.foreground) { _, active in
                if !active { pin = ""; focused = false }
            }
            .privacySensitive()
        }
    }
    private func submit() {
        guard !submitting else { return }
        submitting = true
        let value = pin
        pin = ""
        Task {
            defer { submitting = false }
            if insertionConfirmation {
                do { try await model.continueCardInsertion(prompt) }
                catch is CancellationError { }
                catch MobileError.Cancelled { }
                catch { model.show(error) }
            } else {
                model.answer(prompt, text: value, accepted: true)
            }
        }
    }
}

private func pairingError(_ error: Error) -> String {
    guard case let MobileError.Failed(message) = error else { return error.localizedDescription }
    switch message {
    case "invitation server differs from configured server":
        return String(localized: "The invitation server does not match your configured server.")
    case "invitation expired; obtain a new invitation":
        return String(localized: "This invitation has expired. Ask a member for a new invitation.")
    case "old or unsupported invitation; obtain a new one-use invitation":
        return String(localized: "This invitation format is no longer supported. Ask a member for a new invitation.")
    case "verification code does not match this pending request":
        return String(localized: "This verification code does not match the selected request.")
    case "request no longer pending":
        return String(localized: "This request is no longer waiting for approval.")
    default: return message
    }
}
