use hibiki_lib::{channel::*, e2ee::*, identity::Identity, paths::AppPaths, *};
use std::{collections::BTreeMap, ffi::OsString, path::Path};

fn root() -> (Identity, MembershipProof) {
    let a = Identity::generate("A".into()).unwrap();
    let genesis = ChannelGenesis::create(&a, "work".into(), "verifier").unwrap();
    (
        a,
        MembershipProof {
            genesis,
            events: vec![],
        },
    )
}
fn admit(proof: &mut MembershipProof, issuer: &Identity, subject: &Identity) {
    let state = proof.verify().unwrap();
    let request = JoinRequest::create(subject, &state).unwrap();
    let event = MembershipEvent::create(issuer, &state, MembershipAction::Admit(request)).unwrap();
    proof.events.push(event);
    proof.verify().unwrap();
}
#[test]
fn multilevel_chain_revocation_and_historical_authority() {
    let (a, mut p) = root();
    let b = Identity::generate("B".into()).unwrap();
    let c = Identity::generate("C".into()).unwrap();
    admit(&mut p, &a, &b);
    admit(&mut p, &b, &c);
    let checkpoint = p.verify().unwrap().checkpoint();
    let d = Identity::generate("Other branch".into()).unwrap();
    admit(&mut p, &a, &d);
    let state = p.verify().unwrap();
    assert_eq!(
        state.approved_by(&c.device.id()).unwrap().id(),
        b.device.id()
    );
    assert!(state.can_revoke(&a.device.id(), &c.device.id()));
    assert!(state.can_revoke(&b.device.id(), &c.device.id()));
    for (issuer, target) in [(&c, &a), (&b, &a), (&b, &d), (&b, &b)] {
        assert!(!state.can_revoke(&issuer.device.id(), &target.device.id()));
        let mut invalid = p.clone();
        invalid.events.push(
            MembershipEvent::create(
                issuer,
                &state,
                MembershipAction::Revoke {
                    device_id: target.device.id(),
                },
            )
            .unwrap(),
        );
        assert!(invalid.verify().is_err());
    }
    p.events.push(
        MembershipEvent::create(
            &a,
            &state,
            MembershipAction::Revoke {
                device_id: b.device.id(),
            },
        )
        .unwrap(),
    );
    let state = p
        .verify_from(&p.genesis.hash().unwrap(), &checkpoint)
        .unwrap();
    assert!(state.member(&b.device.id()).is_err());
    assert!(state.member(&c.device.id()).is_ok()); // Revocation is not cascading.
    assert!(state.can_revoke(&a.device.id(), &c.device.id()));
    let mut forged = p.clone();
    forged.events.push(
        MembershipEvent::create(
            &b,
            &state,
            MembershipAction::Revoke {
                device_id: c.device.id(),
            },
        )
        .unwrap(),
    );
    assert!(forged.verify().is_err()); // Historical parent certificate is not active authority.
    p.events.push(
        MembershipEvent::create(
            &a,
            &state,
            MembershipAction::Revoke {
                device_id: c.device.id(),
            },
        )
        .unwrap(),
    );
    assert!(p.verify().unwrap().member(&c.device.id()).is_err());
}

#[test]
fn readmission_cannot_reverse_approval_ancestry() {
    let (a, mut p) = root();
    let b = Identity::generate("B".into()).unwrap();
    let c = Identity::generate("C".into()).unwrap();
    admit(&mut p, &a, &b);
    admit(&mut p, &b, &c);
    p.events
        .push(MembershipEvent::create(&b, &p.verify().unwrap(), MembershipAction::Leave).unwrap());
    let state = p.verify().unwrap();
    let request = JoinRequest::create(&b, &state).unwrap();
    let mut reversed = p.clone();
    reversed
        .events
        .push(MembershipEvent::create(&c, &state, MembershipAction::Admit(request)).unwrap());
    assert!(reversed.verify().is_err());
    admit(&mut p, &a, &b);
    assert!(
        p.verify()
            .unwrap()
            .can_revoke(&b.device.id(), &c.device.id())
    );
}

#[test]
fn key_substitution_signature_tampering_and_cross_channel_fail() {
    let (a, mut p) = root();
    let b = Identity::generate("B".into()).unwrap();
    admit(&mut p, &a, &b);
    let mut tampered = p.clone();
    if let MembershipAction::Admit(r) = &mut tampered.events[0].body.action {
        r.body.device.noise_key[0] ^= 1;
    }
    assert!(tampered.verify().is_err());
    let mut bad = p.clone();
    bad.events[0].signature[0] ^= 1;
    assert!(bad.verify().is_err());
    let (_, other) = root();
    assert!(
        p.verify_from(
            &other.genesis.hash().unwrap(),
            &other.verify().unwrap().checkpoint()
        )
        .is_err()
    );
    let mut reordered = p.clone();
    reordered.events[0].body.sequence = 4;
    assert!(reordered.verify().is_err());
}
#[test]
fn rollback_and_same_height_fork_detected() {
    let (a, root) = root();
    let mut left = root.clone();
    let mut right = root.clone();
    admit(&mut left, &a, &Identity::generate("left".into()).unwrap());
    admit(&mut right, &a, &Identity::generate("right".into()).unwrap());
    let known = left.verify().unwrap().checkpoint();
    assert!(
        root.verify_from(&left.genesis.hash().unwrap(), &known)
            .is_err()
    );
    assert!(
        right
            .verify_from(&left.genesis.hash().unwrap(), &known)
            .is_err()
    );
}
#[test]
fn psk_rotation_invalidates_pending_but_preserves_members() {
    let (a, mut p) = root();
    let b = Identity::generate("B".into()).unwrap();
    admit(&mut p, &a, &b);
    let c = Identity::generate("C".into()).unwrap();
    let stale = JoinRequest::create(&c, &p.verify().unwrap()).unwrap();
    let event = MembershipEvent::create(
        &b,
        &p.verify().unwrap(),
        MembershipAction::ChangePsk {
            verifier_commitment: digest(b"new"),
        },
    )
    .unwrap();
    p.events.push(event);
    assert!(p.verify().unwrap().member(&a.device.id()).is_ok());
    let event =
        MembershipEvent::create(&a, &p.verify().unwrap(), MembershipAction::Admit(stale)).unwrap();
    p.events.push(event);
    assert!(p.verify().is_err());
}
#[test]
fn invite_is_versioned_and_root_bound() {
    let (_, proof) = root();
    let invite = Invite {
        version: 1,
        server: "wss://relay.example/hibiki".into(),
        checkpoint: proof.verify().unwrap().checkpoint(),
        genesis: proof.genesis.clone(),
    };
    let encoded = invite.export().unwrap();
    let decoded = Invite::import(&encoded).unwrap();
    assert_eq!(decoded.genesis, proof.genesis);
    assert!(!encoded.contains("verifier"));
    assert!(Invite::import("hibiki-v2:abcd").is_err());
}
fn transports(channel: &str) -> (Transport, Transport) {
    let a = Identity::generate("A".into()).unwrap();
    let b = Identity::generate("B".into()).unwrap();
    let mut left = Handshake::new(
        &a,
        channel,
        &a.device.id(),
        &b.device.id(),
        "session",
        b.device.noise_key,
        true,
    )
    .unwrap();
    let mut right = Handshake::new(
        &b,
        channel,
        &a.device.id(),
        &b.device.id(),
        "session",
        a.device.noise_key,
        false,
    )
    .unwrap();
    right.read(&left.write().unwrap()).unwrap();
    left.read(&right.write().unwrap()).unwrap();
    right.read(&left.write().unwrap()).unwrap();
    (left.finish().unwrap(), right.finish().unwrap())
}
#[test]
fn noise_encrypts_fragments_and_rejects_replay() {
    let (mut tx, mut rx) = transports("channel");
    let plain = vec![42u8; CHUNK * 3 + 70];
    let packets = tx.encrypt(&plain).unwrap();
    assert_eq!(packets.len(), 4);
    assert!(
        !packets
            .iter()
            .any(|p| p.windows(100).any(|w| w == &plain[..100]))
    );
    let mut recovered = None;
    for p in &packets {
        recovered = rx.decrypt(p).unwrap();
    }
    assert_eq!(recovered.unwrap(), plain);
    assert!(rx.decrypt(&packets[0]).is_err());
}
#[test]
fn noise_detects_wrong_key_context_and_tampering() {
    let a = Identity::generate("A".into()).unwrap();
    let b = Identity::generate("B".into()).unwrap();
    let mut left = Handshake::new(&a, "one", "a", "b", "s", [1; 32], true).unwrap();
    let mut right = Handshake::new(&b, "one", "a", "b", "s", a.device.noise_key, false).unwrap();
    right.read(&left.write().unwrap()).unwrap();
    assert!(left.read(&right.write().unwrap()).is_err());
    let mut left = Handshake::new(&a, "one", "a", "b", "s", b.device.noise_key, true).unwrap();
    let mut right = Handshake::new(&b, "two", "a", "b", "s", a.device.noise_key, false).unwrap();
    right.read(&left.write().unwrap()).unwrap();
    assert!(left.read(&right.write().unwrap()).is_err());
    let (mut tx, mut rx) = transports("c");
    let mut bytes = tx.encrypt(b"private request").unwrap().remove(0);
    bytes[5] ^= 1;
    assert!(rx.decrypt(&bytes).is_err());
}
#[test]
fn xdg_defaults_overrides_and_relative_values() {
    let mut env = BTreeMap::<OsString, OsString>::new();
    let paths = AppPaths::resolve(&env, Path::new("/home/test"), Path::new("/tmp"), 1000);
    assert_eq!(paths.config, Path::new("/home/test/.config/hibiki"));
    assert_eq!(paths.data, Path::new("/home/test/.local/share/hibiki"));
    assert_eq!(paths.runtime, Path::new("/tmp/hibiki-1000"));
    env.insert("XDG_CONFIG_HOME".into(), "relative".into());
    env.insert("XDG_DATA_HOME".into(), "/data".into());
    env.insert("XDG_RUNTIME_DIR".into(), "/run/user/1000".into());
    env.insert(
        "XDG_CONFIG_DIRS".into(),
        "/etc/custom:relative:/etc/xdg".into(),
    );
    let paths = AppPaths::resolve(&env, Path::new("/Users/test"), Path::new("/tmp"), 1000);
    assert_eq!(paths.config, Path::new("/Users/test/.config/hibiki"));
    assert_eq!(paths.data, Path::new("/data/hibiki"));
    assert_eq!(paths.runtime, Path::new("/run/user/1000/hibiki"));
    assert_eq!(paths.config_candidates(None, "client.toml").len(), 3);
    assert_eq!(
        paths.config_candidates(Some(Path::new("/explicit")), "client.toml"),
        vec![Path::new("/explicit")]
    );
    assert!(paths.channel_dir("../../oops").is_err());
}
#[test]
fn psk_hash_is_salted_and_checks_secret() {
    let secret = make_psk();
    let a = hash_psk(&secret).unwrap();
    let b = hash_psk(&secret).unwrap();
    assert_ne!(a, b);
    assert!(a.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
    assert!(check_psk(&secret, &a));
    assert!(!check_psk("incorrect", &a));
}

#[test]
fn initialization_invitation_is_distinct_and_founder_signed() {
    use hibiki_lib::{channel::*, identity::Identity, random_id};
    let identity = Identity::generate("founder".into()).unwrap();
    let invite = EmptyChannelInvite {
        version: 1,
        server: "wss://relay.example/hibiki".into(),
        id: random_id(),
        name: "reserved".into(),
        psk_commitment: [4; 32],
    };
    let text = invite.export().unwrap();
    assert_eq!(EmptyChannelInvite::import(&text).unwrap(), invite);
    assert!(Invite::import(&text).is_err());
    let genesis = invite.founder_genesis(&identity).unwrap();
    assert_eq!(genesis.body.id, invite.id);
    assert_eq!(genesis.body.name, invite.name);
    assert_eq!(genesis.body.founder, identity.device);
    genesis.verify().unwrap();
    let mut changed = genesis;
    changed.body.name = "substituted".into();
    assert!(changed.verify().is_err());
    let mut invalid = invite;
    invalid.version = 2;
    assert!(invalid.export().is_err());
}

#[test]
fn hibiki_version_is_bound_to_authentication_and_noise() {
    use hibiki_lib::{
        encode,
        identity::{Identity, verify},
        protocol::VERSION,
    };
    let a = Identity::generate("a".into()).unwrap();
    let b = Identity::generate("b".into()).unwrap();
    let payload =
        hibiki_lib::wire::authentication_body(VERSION, "nonce", &a.device.id(), &[], &[]).unwrap();
    let signature = a.sign("server-auth/v2", &payload).unwrap();
    verify(
        &a.device.signing_key,
        "server-auth/v2",
        &payload,
        &signature,
    )
    .unwrap();
    assert!(
        verify(
            &a.device.signing_key,
            "server-auth/v2",
            &hibiki_lib::wire::authentication_body(
                "hibiki/invalid",
                "nonce",
                &a.device.id(),
                &[],
                &[]
            )
            .unwrap(),
            &signature
        )
        .is_err()
    );
    let mut initiator =
        Handshake::new(&a, "channel", "a", "b", "session", b.device.noise_key, true).unwrap();
    let wrong_prologue =
        encode(&("hibiki/invalid", "e2ee", "channel", "a", "b", "session")).unwrap();
    let mut responder = snow::Builder::new(hibiki_lib::e2ee::PARAMS.parse().unwrap())
        .local_private_key(b.noise_secret())
        .unwrap()
        .prologue(&wrong_prologue)
        .unwrap()
        .build_responder()
        .unwrap();
    let mut buffer = vec![0; 65535];
    responder
        .read_message(&initiator.write().unwrap(), &mut buffer)
        .unwrap();
    let size = responder.write_message(&[], &mut buffer).unwrap();
    assert!(initiator.read(&buffer[..size]).is_err());
}

#[test]
fn voluntary_leave_requires_fresh_admission_and_preserves_key_pins() {
    let (a, mut proof) = root();
    let b = Identity::generate("B".into()).unwrap();
    admit(&mut proof, &a, &b);
    let old_request = match &proof.events[0].body.action {
        MembershipAction::Admit(r) => r.clone(),
        _ => unreachable!(),
    };
    proof.events.push(
        MembershipEvent::create(&b, &proof.verify().unwrap(), MembershipAction::Leave).unwrap(),
    );
    let state = proof.verify().unwrap();
    assert!(state.member(&b.device.id()).is_err());
    assert!(state.member(&a.device.id()).is_ok());
    let mut reused = proof.clone();
    reused
        .events
        .push(MembershipEvent::create(&a, &state, MembershipAction::Admit(old_request)).unwrap());
    assert!(reused.verify().is_err());
    let mut replaced_request = JoinRequest::create(&b, &state).unwrap();
    let device = &mut replaced_request.body.device;
    device.noise_key = Identity::generate("new-key".into())
        .unwrap()
        .device
        .noise_key;
    device.binding = b
        .sign(
            "device/v1",
            &(&device.name, device.signing_key, device.noise_key),
        )
        .unwrap();
    replaced_request.signature = b.sign("join/v1", &replaced_request.body).unwrap();
    replaced_request.verify().unwrap();
    let mut replaced = proof.clone();
    replaced.events.push(
        MembershipEvent::create(&a, &state, MembershipAction::Admit(replaced_request)).unwrap(),
    );
    assert!(replaced.verify().is_err());
    admit(&mut proof, &a, &b);
    assert!(proof.verify().unwrap().member(&b.device.id()).is_ok());
    proof.events.push(
        MembershipEvent::create(
            &a,
            &proof.verify().unwrap(),
            MembershipAction::Revoke {
                device_id: b.device.id(),
            },
        )
        .unwrap(),
    );
    let state = proof.verify().unwrap();
    let request = JoinRequest::create(&b, &state).unwrap();
    proof
        .events
        .push(MembershipEvent::create(&a, &state, MembershipAction::Admit(request)).unwrap());
    assert!(proof.verify().is_err());
}

#[test]
fn public_key_words_encode_the_complete_public_key_without_secret_material() {
    let a = Identity::generate("device".into()).unwrap();
    let b = Identity::generate("other".into()).unwrap();
    let words = a.device.public_key_words().unwrap();
    assert_eq!(words.split_whitespace().count(), 24);
    let mnemonic = bip39::Mnemonic::parse_in(bip39::Language::English, &words).unwrap();
    assert_eq!(mnemonic.to_entropy(), a.device.signing_key);
    assert_eq!(a.device.clone().public_key_words().unwrap(), words);
    assert_ne!(b.device.public_key_words().unwrap(), words);
    assert_ne!(mnemonic.to_entropy(), a.noise_secret());
}

#[test]
fn embedded_psk_invites_preserve_identity_and_redact_credentials() {
    let (_, proof) = root();
    let invitation = InvitationKind::Member(Invite {
        version: 1,
        server: "wss://example.com/hibiki".into(),
        genesis: proof.genesis.clone(),
        checkpoint: proof.verify().unwrap().checkpoint(),
    });
    let legacy = invitation.export().unwrap();
    assert!(ParsedInvitation::import(&legacy).unwrap().psk.is_none());
    let text = invitation_with_psk(invitation.clone(), "secret-123456".into()).unwrap();
    assert!(text.starts_with("hibiki-psk-v1:"));
    let parsed = ParsedInvitation::import(&text).unwrap();
    assert!(!format!("{parsed:?}").contains("secret"));
    assert_eq!(
        parsed.psk.as_deref().map(|s| s.as_str()),
        Some("secret-123456")
    );
    assert!(parsed.secret(Some("secret-123456".into())).is_err());
    assert_eq!(
        ParsedInvitation::import(&text)
            .unwrap()
            .invitation
            .export()
            .unwrap(),
        legacy
    );
    for secret in ["short".to_string(), "x".repeat(1025)] {
        assert!(invitation_with_psk(invitation.clone(), secret).is_err());
    }
    for text in [
        "hibiki-psk-v1:%%%".to_string(),
        format!("hibiki-psk-v1:{}", "a".repeat(32769)),
        "hibiki-psk-v1:hibiki-psk-v1:x".into(),
    ] {
        assert!(ParsedInvitation::import(&text).is_err());
    }
    let initialization = InvitationKind::Initialization(EmptyChannelInvite {
        version: 1,
        id: random_id(),
        server: "wss://example.com/hibiki".into(),
        name: "Empty".into(),
        psk_commitment: [0; 32],
    });
    let text = invitation_with_psk(initialization, "initial-secret".into()).unwrap();
    assert!(matches!(
        ParsedInvitation::import(&text).unwrap().invitation,
        InvitationKind::Initialization(_)
    ));
}
#[test]
fn renaming_preserves_keys_and_cannot_change_another_member() {
    let (a, mut proof) = root();
    let b = Identity::generate("B".into()).unwrap();
    admit(&mut proof, &a, &b);
    let renamed = b.renamed("New 名称".into()).unwrap();
    assert_eq!(renamed.device.id(), b.device.id());
    assert_eq!(renamed.noise_secret(), b.noise_secret());
    assert_eq!(
        renamed.device.public_key_words().unwrap(),
        b.device.public_key_words().unwrap()
    );
    let action = MembershipAction::Rename {
        device: renamed.device.clone(),
    };
    let mut bad = proof.clone();
    bad.events
        .push(MembershipEvent::create(&a, &bad.verify().unwrap(), action.clone()).unwrap());
    assert!(bad.verify().is_err());
    proof
        .events
        .push(MembershipEvent::create(&b, &proof.verify().unwrap(), action).unwrap());
    assert_eq!(
        proof.verify().unwrap().member(&b.device.id()).unwrap().name,
        "New 名称"
    );
    proof.events.push(
        MembershipEvent::create(&renamed, &proof.verify().unwrap(), MembershipAction::Leave)
            .unwrap(),
    );
    admit(&mut proof, &a, &renamed);
    assert!(proof.verify().is_ok());
    assert!(a.renamed("".into()).is_err());
    assert!(a.renamed("x".repeat(129)).is_err());
}

#[test]
fn subtree_revocation_is_explicit_and_preserves_other_branches() {
    let (a, mut p) = root();
    let b = Identity::generate("B".into()).unwrap();
    let c = Identity::generate("C".into()).unwrap();
    let d = Identity::generate("Sibling".into()).unwrap();
    admit(&mut p, &a, &b);
    admit(&mut p, &b, &c);
    admit(&mut p, &a, &d);
    let state = p.verify().unwrap();
    let mut ids = vec![b.device.id(), c.device.id()];
    ids.sort();
    assert_eq!(state.revocation_subtree(&b.device.id()), ids);
    for (issuer, target) in [(&c, &a), (&b, &b), (&b, &d)] {
        let mut invalid = p.clone();
        invalid.events.push(
            MembershipEvent::create(
                issuer,
                &state,
                MembershipAction::RevokeSubtree {
                    device_id: target.device.id(),
                },
            )
            .unwrap(),
        );
        assert!(invalid.verify().is_err());
    }
    p.events.push(
        MembershipEvent::create(
            &a,
            &state,
            MembershipAction::RevokeSubtree {
                device_id: b.device.id(),
            },
        )
        .unwrap(),
    );
    let state = p.verify().unwrap();
    assert!(state.member(&a.device.id()).is_ok());
    assert!(state.member(&d.device.id()).is_ok());
    for identity in [&b, &c] {
        assert!(state.is_revoked(&identity.device.id()));
        let mut invalid = p.clone();
        let request = JoinRequest::create(identity, &state).unwrap();
        invalid
            .events
            .push(MembershipEvent::create(&a, &state, MembershipAction::Admit(request)).unwrap());
        assert!(invalid.verify().is_err());
    }
}

#[test]
fn reverse_revocation_uses_current_admission_and_exact_thirty_day_boundary() {
    let (a, mut p) = root();
    let b = Identity::generate("B".into()).unwrap();
    let c = Identity::generate("C".into()).unwrap();
    let d = Identity::generate("Sibling".into()).unwrap();
    admit(&mut p, &a, &b);
    admit(&mut p, &b, &c);
    admit(&mut p, &a, &d);
    let state = p.verify().unwrap();
    let available = state
        .reverse_revoke_available_at(&c.device.id(), &a.device.id())
        .unwrap();
    for target in [&a, &b] {
        assert!(!state.can_revoke_at(&c.device.id(), &target.device.id(), available - 1));
        assert!(state.can_revoke_at(&c.device.id(), &target.device.id(), available));
        let mut changed = p.clone();
        let mut event = MembershipEvent::create(
            &c,
            &state,
            MembershipAction::Revoke {
                device_id: target.device.id(),
            },
        )
        .unwrap();
        event.body.issued_at = available;
        event.signature = c.sign("membership/v1", &event.body).unwrap();
        changed.events.push(event);
        assert!(
            changed
                .verify()
                .unwrap()
                .member(&target.device.id())
                .is_err()
        );
        assert!(!state.can_revoke_subtree(&c.device.id(), &target.device.id()));
    }
    assert!(!state.can_revoke_at(&c.device.id(), &d.device.id(), u64::MAX));
    assert!(!state.can_revoke_at(&c.device.id(), &c.device.id(), u64::MAX));
    p.events
        .push(MembershipEvent::create(&c, &state, MembershipAction::Leave).unwrap());
    let state = p.verify().unwrap();
    let mut request = JoinRequest::create(&c, &state).unwrap();
    request.body.created_at = available;
    request.signature = c.sign("join/v1", &request.body).unwrap();
    let mut event = MembershipEvent::create(&b, &state, MembershipAction::Admit(request)).unwrap();
    event.body.issued_at = available;
    event.signature = b.sign("membership/v1", &event.body).unwrap();
    p.events.push(event);
    let state = p.verify().unwrap();
    assert!(!state.can_revoke_at(&c.device.id(), &a.device.id(), available));
    assert!(state.can_revoke_at(&c.device.id(), &a.device.id(), available + 30 * 86400));
}

#[test]
fn protobuf_fragment_transport_handles_every_boundary_and_payload_limit() {
    let (mut tx, mut rx) = transports("fragment-boundaries");
    for size in [1, CHUNK - 1, CHUNK, CHUNK + 1, MAX_PAYLOAD] {
        let plain = vec![17; size];
        let packets = tx.encrypt(&plain).unwrap();
        assert_eq!(packets.len(), size.div_ceil(CHUNK));
        let mut result = None;
        for (i, packet) in packets.iter().enumerate() {
            assert!(packet.len() <= 65535);
            result = rx.decrypt(packet).unwrap();
            assert_eq!(result.is_some(), i + 1 == packets.len());
        }
        assert_eq!(result.unwrap(), plain);
    }
    assert!(tx.encrypt(&[]).is_err());
    assert!(tx.encrypt(&vec![0; MAX_PAYLOAD + 1]).is_err());
    assert!(rx.decrypt(&vec![0; 65536]).is_err());
}
