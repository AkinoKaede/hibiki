use hibiki_lib::invitation::*;
use hibiki_lib::{
    assuan::{self, Line},
    channel::*,
    identity::{Device, Identity, verify},
    protocol::*,
    wire::{self, Wire, pb},
};
use prost::Message;
use prost_types::{DescriptorProto, FileDescriptorSet};
use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}
fn identity() -> Identity {
    // Synthetic test keys only. This also locks the original identity storage format.
    hibiki_lib::decode(&std::fs::read(fixture("wire-identity.postcard")).unwrap()).unwrap()
}
fn trust() -> (Identity, ChannelGenesis, MembershipProof) {
    let identity = identity();
    let genesis = ChannelGenesis::create(&identity, "a".repeat(32), "wire-test".into()).unwrap();
    let proof = MembershipProof {
        genesis: genesis.clone(),
        events: vec![],
    };
    (identity, genesis, proof)
}
fn operation() -> Operation {
    Operation {
        id: "c".repeat(32),
        channel: "a".repeat(32),
        initiator: identity().device.id(),
        service: ServiceKind::Scdaemon,
        deadline: 42,
        state: OperationState::Pending,
        targets: vec![OperationTarget {
            device: "d".repeat(32),
            state: TargetState::Executing,
        }],
    }
}
fn event(action: MembershipAction) -> MembershipEvent {
    let identity = identity();
    let body = EventBody {
        channel_id: "a".repeat(32),
        sequence: 1,
        previous_event_hash: trust().1.hash().unwrap(),
        action,
        issuer_device_id: identity.device.id(),
        issued_at: 1,
    };
    MembershipEvent {
        signature: identity.sign("membership/v4", &body).unwrap(),
        body,
    }
}
fn modern() -> (AdmissionRequest, OneTimeInvitation) {
    let identity = identity();
    let genesis = ChannelGenesis::create(&identity, "a".repeat(32), "wire-test".into()).unwrap();
    let state = MembershipProof {
        genesis,
        events: vec![],
    }
    .verify()
    .unwrap();
    let mut request = AdmissionRequest::create(&identity, &state, "b".repeat(32), 0).unwrap();
    request.body.nonce = "c".repeat(32);
    request.body.created_at = 1;
    request.signature = identity.sign("join/v4", &request.body).unwrap();
    let invitation = OneTimeInvitation {
        metadata: InvitationMetadata {
            id: "b".repeat(32),
            server: "wss://example.test/hibiki".into(),
            channel: state.id.clone(),
            name: state.name.clone(),
            genesis_hash: Some(state.genesis_hash),
            checkpoint: state.checkpoint(),
            issuer_admission: state.admission_id(&identity.device.id()).unwrap().into(),
            expires_at: 86401,
            key_hash: hibiki_lib::digest(&[3; 32]),
        },
        key: [3; 32],
    };
    (request, invitation)
}
fn envelopes() -> Vec<Envelope> {
    let (admission, invitation) = modern();
    let (identity, genesis, proof) = trust();
    let id = "id".to_owned();
    let channel = "channel".to_owned();
    let peer = "peer".to_owned();
    let request = "request".to_owned();
    let mut messages = vec![
        Envelope::OperationReady {
            id: id.clone(),
            peer: peer.clone(),
        },
        Envelope::OperationChanged { id: id.clone() },
        Envelope::Hello {
            version: VERSION.into(),
            nonce: "nonce".into(),
            capabilities: vec![],
        },
        Envelope::Hello {
            version: VERSION.into(),
            nonce: "nonce".into(),
            capabilities: vec!["future/query".into()],
        },
        Envelope::Authenticate {
            device: identity.device.clone(),
            signature: vec![9; 64],
            capabilities: vec![],
        },
        Envelope::Authenticated {
            capabilities: vec![],
        },
        Envelope::Relay {
            channel: channel.clone(),
            peer: peer.clone(),
            session: id.clone(),
            data: vec![0, 1, 255],
        },
        Envelope::Relay {
            channel: channel.clone(),
            peer: peer.clone(),
            session: id.clone(),
            data: vec![],
        },
        Envelope::RelayFailure {
            session: id.clone(),
            peer: peer.clone(),
            error: WireError::new("failed", "test"),
        },
        Envelope::ChannelChanged {
            channel: channel.clone(),
        },
        Envelope::PeerOnline { peer: peer.clone() },
        Envelope::PeerOffline { peer: peer.clone() },
        Envelope::Response {
            id: id.clone(),
            result: Err(WireError::new("unsupported", "test")),
        },
    ];
    let mut controls = vec![
        Control::Queue {
            operation: operation(),
        },
        Control::ResumeOperation { id: id.clone() },
        Control::OperationStatus { id: id.clone() },
        Control::ClaimOperation {
            id: id.clone(),
            initiator: peer.clone(),
            channel: channel.clone(),
            service: ServiceKind::Pinentry,
        },
        Control::TargetDone {
            id: id.clone(),
            success: false,
        },
        Control::AbandonTarget {
            id: id.clone(),
            peer: peer.clone(),
        },
        Control::EndOperation {
            id: id.clone(),
            completed: true,
        },
        Control::Create {
            genesis: genesis.clone(),
        },
        Control::GetChannel {
            channel: channel.clone(),
        },
        Control::ListChannels,
        Control::RegisterInvitation {
            metadata: invitation.metadata.clone(),
        },
        Control::ResolveInvitation {
            invitation: invitation.clone(),
        },
        Control::ChannelSnapshot {
            channel: channel.clone(),
        },
        Control::Join {
            request: admission.clone(),
            invitation: invitation.clone(),
        },
        Control::Pending {
            channel: channel.clone(),
        },
        Control::Announce {
            channels: vec![channel.clone()],
        },
        Control::Peers {
            channel: channel.clone(),
        },
        Control::Claim {
            genesis,
            invitation: invitation.clone(),
        },
        Control::Policy,
        Control::RejectJoin {
            channel: channel.clone(),
            request: request.clone(),
        },
        Control::WithdrawJoin {
            channel: channel.clone(),
            request: request.clone(),
        },
        Control::JoinStatus {
            channel: channel.clone(),
            request,
        },
        Control::WithdrawPending { channel },
    ];
    for action in [
        MembershipAction::Accept(admission.clone()),
        MembershipAction::Revoke {
            device_id: peer.clone(),
        },
        MembershipAction::Leave,
        MembershipAction::Rename {
            device: identity.device.clone(),
        },
        MembershipAction::RevokeSubtree {
            device_id: peer.clone(),
        },
    ] {
        controls.push(Control::Append {
            event: event(action),
        });
    }
    controls.push(Control::Append {
        event: event(MembershipAction::Leave),
    });
    messages.extend(controls.into_iter().map(|command| Envelope::Request {
        id: id.clone(),
        command,
    }));
    let mut replies = vec![
        Reply::Operation(operation()),
        Reply::Ok,
        Reply::Proof(proof.clone()),
        Reply::Proofs(vec![proof.clone()]),
        Reply::ChannelSnapshot {
            proof: proof.clone(),
            online: vec![peer.clone()],
            revoked: vec![peer.clone()],
        },
        Reply::Requests(vec![admission.clone()]),
        Reply::InvitationProof {
            proof: proof.clone(),
            access_revision: 1,
        },
        Reply::Peers(vec![peer]),
        Reply::Policy {
            allow_client_channel_creation: false,
        },
    ];
    replies
        .extend([JoinState::Pending, JoinState::Member, JoinState::Absent].map(Reply::JoinStatus));
    messages.extend(replies.into_iter().map(|reply| Envelope::Response {
        id: id.clone(),
        result: Ok(reply),
    }));
    messages
}
fn inputs() -> Vec<SessionInput> {
    vec![
        SessionInput::PrepareCard {
            id: "prepare".into(),
            target: CardTarget {
                serial: Some("ABCD".into()),
                key: None,
            },
        },
        SessionInput::PrepareCard {
            id: "prepare".into(),
            target: CardTarget {
                serial: None,
                key: Some("OPENPGP.1".into()),
            },
        },
        SessionInput::CancelPreparation {
            id: "prepare".into(),
        },
        SessionInput::Execute {
            request: 1,
            preparation: vec![Line::from("SETDATA 00")],
            line: "PKSIGN".into(),
        },
        SessionInput::Command {
            request: 2,
            line: "SERIALNO".into(),
        },
        SessionInput::InquiryReply {
            request: 3,
            line: "D test-pin".into(),
        },
    ]
}
fn private_messages() -> Vec<PrivateMessage> {
    let proof = trust().2;
    let mut messages = vec![
        PrivateMessage::PingOpen {
            proof: proof.clone(),
            capabilities: vec![],
        },
        PrivateMessage::PingOpened {
            proof: proof.clone(),
            capabilities: vec![],
        },
        PrivateMessage::Ping {
            nonce: "nonce".into(),
        },
        PrivateMessage::Pong {
            nonce: "nonce".into(),
        },
        PrivateMessage::OpenService {
            proof: proof.clone(),
            service: ServiceKind::Scdaemon,
            capabilities: vec![],
        },
        PrivateMessage::ServiceOpened {
            proof: proof.clone(),
            enabled: false,
            capabilities: vec![],
        },
        PrivateMessage::Output(SessionOutput::Line {
            request: 1,
            line: "OK".into(),
        }),
        PrivateMessage::Output(SessionOutput::Failure),
        PrivateMessage::OutputBatch {
            request: 1,
            lines: vec!["S SERIALNO ABCD".into(), "OK".into()],
        },
        PrivateMessage::Close,
        PrivateMessage::Closed,
        PrivateMessage::Failure,
    ];
    for state in [
        CardPreparation::Waiting,
        CardPreparation::Ready {
            serial: "ABCD".into(),
        },
        CardPreparation::Unavailable,
    ] {
        messages.push(PrivateMessage::Output(SessionOutput::CardStatus {
            id: "prepare".into(),
            state,
        }));
    }
    for input in inputs() {
        messages.push(PrivateMessage::Input(input.clone()));
        messages.push(PrivateMessage::Execute {
            id: "operation".into(),
            input,
        });
    }
    messages
}
fn roundtrip<T: Wire + serde::Serialize>(value: &T)
where
    T::Proto: Message + Default + zeroize::Zeroize,
{
    let before = hibiki_lib::encode(value).unwrap();
    let bytes = wire::encode(value).unwrap();
    let decoded: T = wire::decode(&bytes).unwrap();
    assert_eq!(before, hibiki_lib::encode(&decoded).unwrap());
    assert_eq!(wire::encode_secret(value).unwrap().as_slice(), bytes);
    // Ordinary unknown fields are ignored without altering the business value.
    let mut future = bytes.clone();
    future.extend_from_slice(&[0xa2, 0x06, 0x03, 1, 2, 3]);
    assert_eq!(
        before,
        hibiki_lib::encode(&wire::decode::<T>(&future).unwrap()).unwrap()
    );
    assert!(wire::decode::<T>(&bytes[..bytes.len() - 1]).is_err());
}
#[test]
fn every_network_variant_roundtrips_and_ignores_unknown_fields() {
    for value in envelopes() {
        roundtrip(&value);
    }
    for value in private_messages() {
        roundtrip(&value);
    }
    for state in [
        OperationState::Pending,
        OperationState::Completed,
        OperationState::Canceled,
        OperationState::Expired,
    ] {
        let mut op = operation();
        op.state = state;
        for target in [
            TargetState::Pending,
            TargetState::Executing,
            TargetState::Succeeded,
            TargetState::Failed,
        ] {
            op.targets[0].state = target;
            roundtrip(&op);
        }
    }
}

#[test]
fn explicit_card_rejection_roundtrips_with_baseline_unavailable_fallback() {
    let value = PrivateMessage::Output(SessionOutput::CardStatus {
        id: "prepare".into(),
        state: CardPreparation::Rejected,
    });
    roundtrip(&value);
    // Independent baseline shape: its empty unavailable message ignores the
    // additive rejection field, preserving old peers' failure behavior.
    #[derive(Clone, PartialEq, Message)]
    struct OldPreparation {
        #[prost(message, optional, tag = "3")]
        unavailable: Option<Empty>,
    }
    #[derive(Clone, PartialEq, Message)]
    struct Empty {}
    let bytes = wire::encode(&CardPreparation::Rejected).unwrap();
    let old = OldPreparation::decode(bytes.as_slice()).unwrap();
    assert!(old.unavailable.is_some());
    assert!(matches!(
        wire::decode::<CardPreparation>(&old.encode_to_vec()).unwrap(),
        CardPreparation::Unavailable
    ));
    assert!(matches!(
        wire::decode::<CardPreparation>(&bytes).unwrap(),
        CardPreparation::Rejected
    ));
}
#[test]
fn baseline_byte_fixtures_are_stable() {
    let expected = std::fs::read_to_string(fixture("wire-v4.hex")).unwrap();
    let actual = fixture_bytes();
    assert_eq!(
        actual, expected,
        "baseline bytes changed; do not regenerate published fixtures"
    );
}
fn fixture_bytes() -> String {
    let mut lines = vec![];
    for (i, value) in envelopes().iter().enumerate() {
        lines.push(format!(
            "envelope-{i} {}",
            hex::encode(wire::encode(value).unwrap())
        ));
    }
    for (i, value) in private_messages().iter().enumerate() {
        lines.push(format!(
            "private-{i} {}",
            hex::encode(wire::encode(value).unwrap())
        ));
    }
    lines.join("\n") + "\n"
}
#[test]
#[ignore = "one-time unpublished baseline creation; never regenerate a published baseline"]
fn create_unpublished_baseline() {
    assert!(
        !fixture("wire-v4.hex").exists(),
        "v4 baseline already exists"
    );
    std::fs::write(fixture("wire-v4.hex"), fixture_bytes()).unwrap();
    std::fs::write(
        fixture("wire-v4.descriptor"),
        include_bytes!(concat!(env!("OUT_DIR"), "/hibiki-v4.bin")),
    )
    .unwrap();
}
#[test]
fn unknown_required_messages_and_enums_are_rejected() {
    for bytes in [&[][..], &[0xa2, 0x06, 0][..]] {
        assert!(wire::decode::<Envelope>(bytes).is_err());
        assert!(wire::decode::<PrivateMessage>(bytes).is_err());
        assert!(wire::decode::<MembershipAction>(bytes).is_err());
    }
    assert!(wire::decode::<Envelope>(&[0x32, 0]).is_err()); // Request without command
    assert!(wire::decode::<Envelope>(&[0x3a, 0]).is_err()); // Response without result
    assert!(wire::decode::<PrivateMessage>(&[0x3a, 0]).is_err()); // Execute without input
    assert!(wire::decode::<SessionOutput>(&[0x0a, 0]).is_err()); // CardStatus without state
    for value in [0, -1, 99] {
        assert!(ServiceKind::from_proto(&value).is_err());
        assert!(JoinState::from_proto(&value).is_err());
        assert!(OperationState::from_proto(&value).is_err());
        assert!(TargetState::from_proto(&value).is_err());
        let mut op = operation().to_proto();
        op.service = value;
        assert!(wire::decode::<Operation>(&op.encode_to_vec()).is_err());
    }
}
#[test]
fn malformed_keys_signatures_card_targets_and_oversized_messages_are_rejected() {
    let original = identity().device.to_proto();
    for n in [0, 31, 33] {
        let mut key = original.clone();
        key.signing_key = vec![1; n];
        assert!(wire::decode::<Device>(&key.encode_to_vec()).is_err());
        let mut key = original.clone();
        key.noise_key = vec![1; n];
        assert!(wire::decode::<Device>(&key.encode_to_vec()).is_err());
    }
    let mut key = original;
    key.binding.pop();
    assert!(wire::decode::<Device>(&key.encode_to_vec()).is_err());
    let mut auth = envelopes()[4].to_proto();
    if let Some(pb::envelope::Kind::Authenticate(value)) = &mut auth.kind {
        value.signature.pop();
    }
    assert!(wire::decode::<Envelope>(&auth.encode_to_vec()).is_err());
    assert!(wire::decode::<Envelope>(&vec![0; MAX_WIRE + 1]).is_err());
    assert!(wire::decode::<PrivateMessage>(&vec![0; hibiki_lib::e2ee::MAX_PAYLOAD + 1]).is_err());
    let oversized = Envelope::Relay {
        channel: String::new(),
        peer: String::new(),
        session: String::new(),
        data: vec![0; MAX_WIRE],
    };
    assert!(wire::encode(&oversized).is_err());
    let batch = PrivateMessage::OutputBatch {
        request: 1,
        lines: vec!["OK".into(); assuan::MAX_LINES + 1],
    };
    assert!(wire::encode(&batch).is_err());
    assert!(wire::decode::<PrivateMessage>(&batch.to_proto().encode_to_vec()).is_err());
    let line = PrivateMessage::Input(SessionInput::Command {
        request: 1,
        line: "BAD\nLINE".into(),
    });
    assert!(wire::encode(&line).is_err());
    assert!(wire::decode::<PrivateMessage>(&line.to_proto().encode_to_vec()).is_err());
    let target = CardTarget {
        serial: Some(String::new()),
        key: None,
    };
    assert!(wire::decode::<CardTarget>(&target.to_proto().encode_to_vec()).is_err());
}
#[test]
fn capabilities_default_to_baseline_and_are_normalized_authenticated_and_bounded() {
    let strings = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    let server = strings(&["b", "a", "a"]);
    let client = strings(&["c", "a"]);
    assert_eq!(
        wire::negotiate_capabilities(&server, &client).unwrap(),
        strings(&["a"])
    );
    assert!(
        wire::negotiate_capabilities(&server, &[])
            .unwrap()
            .is_empty()
    );
    assert!(wire::validate_negotiated(&server, &strings(&["c"])).is_err());
    for invalid in [
        strings(&[""]),
        strings(&["bad name"]),
        vec!["a".into(); 65],
        vec!["a".repeat(129)],
    ] {
        assert!(wire::normalize_capabilities(&invalid).is_err());
    }
    let identity = identity();
    let body = wire::authentication_body(VERSION, "nonce", &identity.device.id(), &server, &client)
        .unwrap();
    let signature = identity.sign("server-auth/v4", &body).unwrap();
    let normalized = wire::authentication_body(
        VERSION,
        "nonce",
        &identity.device.id(),
        &strings(&["a", "b"]),
        &client,
    )
    .unwrap();
    verify(
        &identity.device.signing_key,
        "server-auth/v4",
        &normalized,
        &signature,
    )
    .unwrap();
    for changed in [
        wire::authentication_body(VERSION, "nonce", &identity.device.id(), &[], &client).unwrap(),
        wire::authentication_body(VERSION, "nonce", &identity.device.id(), &server, &[]).unwrap(),
        wire::authentication_body("hibiki/2", "nonce", &identity.device.id(), &server, &client)
            .unwrap(),
    ] {
        assert!(
            verify(
                &identity.device.signing_key,
                "server-auth/v4",
                &changed,
                &signature
            )
            .is_err()
        );
    }
    let Envelope::Hello { capabilities, .. } =
        wire::decode::<Envelope>(&hex::decode("1a110a08686962696b692f3212056e6f6e6365").unwrap())
            .unwrap()
    else {
        panic!()
    };
    assert!(capabilities.is_empty());
}
#[test]
fn network_conversion_preserves_signed_history_hashes_and_postcard_storage() {
    let (identity, genesis, proof) = trust();
    let renamed = identity.renamed("new-name".into()).unwrap();
    let rename = event(MembershipAction::Rename {
        device: renamed.device.clone(),
    });
    let proof = MembershipProof {
        events: vec![rename],
        ..proof
    };
    let decoded: MembershipProof = wire::decode(&wire::encode(&proof).unwrap()).unwrap();
    assert_eq!(proof, decoded);
    decoded.verify().unwrap();
    assert_eq!(
        proof.genesis.hash().unwrap(),
        decoded.genesis.hash().unwrap()
    );
    assert_eq!(
        proof.events[0].hash().unwrap(),
        decoded.events[0].hash().unwrap()
    );
    assert_eq!(
        proof.verify().unwrap().checkpoint(),
        decoded.verify().unwrap().checkpoint()
    );
    let invite = Invite {
        version: 1,
        server: "ws://localhost/hibiki".into(),
        genesis,
        checkpoint: proof.verify().unwrap().checkpoint(),
    };
    assert_eq!(
        hibiki_lib::decode::<Invite>(&hibiki_lib::encode(&invite).unwrap())
            .unwrap()
            .genesis,
        decoded.genesis
    );
    let stored = hibiki_lib::encode(&decoded).unwrap();
    assert_eq!(
        hibiki_lib::decode::<MembershipProof>(&stored).unwrap(),
        proof
    );
    assert_eq!(hibiki_lib::encode(&proof).unwrap(), stored);
}

fn check_message(old: &DescriptorProto, new: &DescriptorProto) {
    for field in &old.field {
        let next = new
            .field
            .iter()
            .find(|next| next.number == field.number)
            .expect("baseline field removed");
        assert_eq!(
            (
                &field.name,
                &field.label,
                &field.r#type,
                &field.type_name,
                &field.default_value,
                &field.proto3_optional
            ),
            (
                &next.name,
                &next.label,
                &next.r#type,
                &next.type_name,
                &next.default_value,
                &next.proto3_optional
            ),
            "baseline field changed"
        );
        let oneof = |message: &DescriptorProto, index: Option<i32>| {
            index.map(|i| message.oneof_decl[i as usize].name.clone())
        };
        assert_eq!(oneof(old, field.oneof_index), oneof(new, next.oneof_index));
    }
    for nested in &old.nested_type {
        check_message(
            nested,
            new.nested_type
                .iter()
                .find(|next| next.name == nested.name)
                .expect("baseline nested type removed"),
        );
    }
}
#[test]
fn published_schema_field_numbers_types_and_enum_values_are_frozen() {
    let old = FileDescriptorSet::decode(
        std::fs::read(fixture("wire-v4.descriptor"))
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    let new = FileDescriptorSet::decode(
        include_bytes!(concat!(env!("OUT_DIR"), "/hibiki-v4.bin")).as_slice(),
    )
    .unwrap();
    for file in old.file {
        let next = new
            .file
            .iter()
            .find(|next| next.name == file.name)
            .expect("baseline file removed");
        assert_eq!(file.package, next.package);
        assert_eq!(file.syntax, next.syntax);
        for message in file.message_type {
            check_message(
                &message,
                next.message_type
                    .iter()
                    .find(|next| next.name == message.name)
                    .expect("baseline message removed"),
            );
        }
        for enumeration in file.enum_type {
            let next = next
                .enum_type
                .iter()
                .find(|next| next.name == enumeration.name)
                .expect("baseline enum removed");
            for value in enumeration.value {
                assert!(
                    next.value
                        .iter()
                        .any(|next| next.name == value.name && next.number == value.number),
                    "baseline enum value changed"
                );
            }
        }
    }
}

// Independent tiny baseline decoder: it has no access to future Hello fields.
mod baseline {
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Hello {
        #[prost(string, tag = "1")]
        pub version: String,
        #[prost(string, tag = "2")]
        pub nonce: String,
        #[prost(string, repeated, tag = "3")]
        pub capabilities: Vec<String>,
    }
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Envelope {
        #[prost(message, optional, tag = "3")]
        pub hello: Option<Hello>,
    }
}
#[test]
fn independent_baseline_and_future_decoders_interoperate() {
    #[derive(Clone, PartialEq, Message)]
    struct FutureHello {
        #[prost(string, tag = "1")]
        version: String,
        #[prost(string, tag = "2")]
        nonce: String,
        #[prost(string, repeated, tag = "3")]
        capabilities: Vec<String>,
        #[prost(string, optional, tag = "100")]
        addition: Option<String>,
    }
    #[derive(Clone, PartialEq, Message)]
    struct FutureEnvelope {
        #[prost(message, optional, tag = "3")]
        hello: Option<FutureHello>,
    }
    let old = baseline::Envelope {
        hello: Some(baseline::Hello {
            version: VERSION.into(),
            nonce: "nonce".into(),
            capabilities: vec![],
        }),
    };
    let future = FutureEnvelope::decode(old.encode_to_vec().as_slice()).unwrap();
    assert!(future.hello.as_ref().unwrap().addition.is_none());
    let Envelope::Hello { capabilities, .. } =
        wire::decode::<Envelope>(&old.encode_to_vec()).unwrap()
    else {
        panic!()
    };
    assert!(capabilities.is_empty());
    let mut future = future;
    future.hello.as_mut().unwrap().addition = Some("new-value".into());
    let bytes = future.encode_to_vec();
    assert_eq!(baseline::Envelope::decode(bytes.as_slice()).unwrap(), old);
    let Envelope::Hello {
        version,
        nonce,
        capabilities,
    } = wire::decode::<Envelope>(&bytes).unwrap()
    else {
        panic!()
    };
    assert_eq!(version, VERSION);
    assert_eq!(nonce, "nonce");
    assert!(capabilities.is_empty());
}
#[test]
fn generated_private_allocations_zeroize_recursively() {
    use zeroize::Zeroize;
    let mut value = PrivateMessage::Execute {
        id: "id".into(),
        input: SessionInput::Execute {
            request: 1,
            preparation: vec!["SETDATA secret".into()],
            line: "PKSIGN secret".into(),
        },
    }
    .to_proto();
    value.zeroize();
    assert!(value.kind.is_none());
}

#[test]
fn duplicate_fields_and_allocation_amplification_are_rejected_before_decode() {
    let bytes = wire::encode(&PrivateMessage::Close).unwrap();
    let mut duplicate = bytes.clone();
    duplicate.extend_from_slice(&bytes);
    assert!(wire::decode::<PrivateMessage>(&duplicate).is_err());
    let mut ambiguous = bytes;
    ambiguous.extend_from_slice(&wire::encode(&PrivateMessage::Failure).unwrap());
    assert!(wire::decode::<PrivateMessage>(&ambiguous).is_err());
    // Duplicate secret bytes, with a larger replacement that would grow the first allocation.
    assert!(
        wire::decode::<SessionInput>(&[
            0x22, 0x0b, 0x12, 0x02, b'A', b'A', 0x12, 0x05, b'B', b'B', b'B', b'B', b'B'
        ])
        .is_err()
    );
    // 65,536 empty nested targets would allocate before required enum validation.
    let mut op = operation().to_proto();
    op.targets = vec![pb::OperationTarget::default(); 65_536];
    assert!(wire::decode::<Operation>(&op.encode_to_vec()).is_err());
    assert!(
        wire::decode::<Envelope>(&[
            0xa2, 0x06, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02
        ])
        .is_err()
    );
    // Unknown scalar, fixed-width and group fields remain skippable.
    let mut bytes = wire::encode(&Envelope::Authenticated {
        capabilities: vec![],
    })
    .unwrap();
    bytes.extend_from_slice(&[
        0xa0, 0x06, 1, 0xa1, 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0xa5, 0x06, 0, 0, 0, 0, 0xa3, 0x06,
        0x08, 1, 0xa4, 0x06,
    ]);
    assert!(wire::decode::<Envelope>(&bytes).is_ok());
}
