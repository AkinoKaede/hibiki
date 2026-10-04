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
    let event = MembershipEvent::create(
        &c,
        &p.verify().unwrap(),
        MembershipAction::Revoke {
            device_id: a.device.id(),
        },
    )
    .unwrap();
    p.events.push(event);
    let state = p
        .verify_from(&p.genesis.hash().unwrap(), &checkpoint)
        .unwrap();
    assert!(state.member(&a.device.id()).is_err());
    assert!(state.member(&b.device.id()).is_ok());
    assert!(state.member(&c.device.id()).is_ok());
    // A valid historical certificate does not let a revoked founder sign new events.
    let illegal = MembershipEvent::create(
        &a,
        &state,
        MembershipAction::Revoke {
            device_id: b.device.id(),
        },
    )
    .unwrap();
    p.events.push(illegal);
    assert!(p.verify().is_err());
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
    let payload = (VERSION, "nonce", a.device.id());
    let signature = a.sign("server-auth/v1", &payload).unwrap();
    verify(
        &a.device.signing_key,
        "server-auth/v1",
        &payload,
        &signature,
    )
    .unwrap();
    assert!(
        verify(
            &a.device.signing_key,
            "server-auth/v1",
            &("hibiki/1", "nonce", a.device.id()),
            &signature
        )
        .is_err()
    );
    let mut initiator =
        Handshake::new(&a, "channel", "a", "b", "session", b.device.noise_key, true).unwrap();
    let wrong_prologue = encode(&("hibiki/1", "e2ee", "channel", "a", "b", "session")).unwrap();
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
