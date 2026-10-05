use hibiki_lib::{channel::*, identity::Identity, invitation::*, *};
mod common;
use common::*;

#[test]
fn invitations_have_distinct_keys_compact_payloads_and_redacted_debug() {
    let (a, p) = root();
    let state = p.verify().unwrap();
    let create = || {
        OneTimeInvitation::new(
            "wss://example.com/hibiki".into(),
            state.id.clone(),
            state.name.clone(),
            Some((&state, &a.device.id())),
        )
        .unwrap()
    };
    let before = now();
    let one = create();
    let two = create();
    assert_ne!(one.key, two.key);
    assert_ne!(one.metadata.id, two.metadata.id);
    assert!((before + INVITATION_TTL..=now() + INVITATION_TTL).contains(&one.metadata.expires_at));
    let text = one.export().unwrap();
    assert!(text.len() < 1024);
    let parsed = OneTimeInvitation::import(&text).unwrap();
    assert_eq!(parsed.key, one.key);
    assert_eq!(parsed.metadata, one.metadata);
    assert!(!format!("{parsed:?}").contains(&hex::encode(one.key)));
    assert!(
        !format!(
            "{:?}",
            protocol::Control::ResolveInvitation { invitation: one }
        )
        .contains(&text[..])
    );
    assert!(OneTimeInvitation::import("hibiki-invite-v2:%%%").is_err());
    assert!(OneTimeInvitation::import(&format!("hibiki-invite-v2:{}", "A".repeat(4097))).is_err());
}
#[test]
fn verification_codes_bind_the_exact_signed_request_and_cannot_be_invitations() {
    let (_, p) = root();
    let b = Identity::generate("applicant".into()).unwrap();
    let req = AdmissionRequest::create(&b, &p.verify().unwrap(), random_id(), 0).unwrap();
    let code = VerificationCode::new("wss://example.com/hibiki".into(), &req).unwrap();
    let text = code.export().unwrap();
    VerificationCode::import(&text)
        .unwrap()
        .matches(&code.server, &req)
        .unwrap();
    assert!(OneTimeInvitation::import(&text).is_err());
    assert!(code.matches("wss://other.test/hibiki", &req).is_err());
    let other =
        AdmissionRequest::create(&b, &p.verify().unwrap(), req.body.invitation_id.clone(), 0)
            .unwrap();
    assert!(code.matches(&code.server, &other).is_err());
    let mut bad = req;
    bad.signature[0] ^= 1;
    assert!(code.matches(&code.server, &bad).is_err());
    assert!(VerificationCode::import("hibiki-invite-v2:whatever").is_err());
}
#[test]
fn readmission_tracks_rounds_preserves_old_descendants_and_restarts_clock() {
    let (a, mut p) = root();
    let b = Identity::generate("b".into()).unwrap();
    let c = Identity::generate("c".into()).unwrap();
    let old = admit(&mut p, &a, &b);
    admit(&mut p, &b, &c);
    append(
        &mut p,
        &a,
        MembershipAction::Revoke {
            device_id: b.device.id(),
        },
    );
    // A former descendant may approve the new round; this is not an ancestry cycle.
    admit(&mut p, &c, &b);
    let state = p.verify().unwrap();
    assert!(state.can_revoke(&c.device.id(), &b.device.id()));
    assert!(!state.can_revoke(&b.device.id(), &c.device.id()));
    let at = state
        .reverse_revoke_available_at(&b.device.id(), &c.device.id())
        .unwrap();
    assert!(!state.can_revoke_at(&b.device.id(), &c.device.id(), at - 1));
    assert!(state.can_revoke_at(&b.device.id(), &c.device.id(), at));
    assert!(state.validate_admission(&old).is_err());
    // The original founder can also return under a new round.
    let founder = AdmissionRequest::create(&a, &state, random_id(), 1).unwrap();
    append(&mut p, &b, MembershipAction::Accept(founder));
    let state = p.verify().unwrap();
    assert!(!state.can_revoke(&a.device.id(), &b.device.id()));
    assert!(state.can_revoke(&b.device.id(), &a.device.id()));
}
#[test]
fn removed_id_cannot_replay_an_unsubmitted_request_or_reuse_an_invitation() {
    let (a, mut p) = root();
    let b = Identity::generate("b".into()).unwrap();
    admit(&mut p, &a, &b);
    let stale = AdmissionRequest::create(&b, &p.verify().unwrap(), random_id(), 0).unwrap();
    append(
        &mut p,
        &a,
        MembershipAction::Revoke {
            device_id: b.device.id(),
        },
    );
    assert!(p.verify().unwrap().validate_admission(&stale).is_err());
    let accepted = admit(&mut p, &a, &b);
    append(
        &mut p,
        &a,
        MembershipAction::Revoke {
            device_id: b.device.id(),
        },
    );
    let duplicate =
        AdmissionRequest::create(&b, &p.verify().unwrap(), accepted.body.invitation_id, 0).unwrap();
    assert!(p.verify().unwrap().validate_admission(&duplicate).is_err());
}
#[test]
fn qr_images_have_valid_png_and_full_quiet_zone() {
    let text = "hibiki-verify-v1:fixture";
    let bytes = qr::png(text).unwrap();
    assert!(bytes.starts_with(b"\x89PNG\r\n\x1a\n"));
    let rendered = qr::terminal(text).unwrap();
    let rows = rendered.lines().collect::<Vec<_>>();
    assert!(rows[0].trim().is_empty() && rows[1].trim().is_empty());
    assert!(
        rows.iter()
            .all(|line| line.starts_with("    ") && line.ends_with("    "))
    );
}
