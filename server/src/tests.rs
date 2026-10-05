/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Kaede Akino
 */

use super::db::Database;
use hibiki_lib::{channel::*, identity::Identity, invitation::*, now, random_id};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

#[test]
fn server_defaults_and_shipped_configs_use_system_storage_and_admin_creation() {
    for config in [
        super::Config::default(),
        toml::from_str("").unwrap(),
        toml::from_str(include_str!("../../examples/server.toml")).unwrap(),
        toml::from_str(include_str!("../server.toml")).unwrap(),
    ] {
        assert_eq!(
            config.database,
            std::path::Path::new("/var/lib/hibiki/hibiki.sqlite3")
        );
        assert!(!config.allow_client_channel_creation);
    }
}

#[test]
fn config_search_falls_back_to_local_and_prefers_system_without_merging() {
    let dir = tempfile::tempdir().unwrap();
    let [system, local] = super::CONFIG_PATHS.map(|path| dir.path().join(&path[1..]));
    let candidates = [system.as_path(), local.as_path()];
    let (config, selected) = super::load_config(None, &candidates).unwrap();
    assert!(selected.is_none());
    assert_eq!(config.database, super::Config::default().database);

    std::fs::create_dir_all(local.parent().unwrap()).unwrap();
    std::fs::write(&local, "listen = '127.0.0.1:9000'\n").unwrap();
    let (config, selected) = super::load_config(None, &candidates).unwrap();
    assert_eq!(selected.as_deref(), Some(local.as_path()));
    assert_eq!(config.listen, "127.0.0.1:9000");
    assert_eq!(config.database, super::Config::default().database);

    std::fs::create_dir_all(system.parent().unwrap()).unwrap();
    std::fs::write(&system, "database = 'data/system.sqlite3'\n").unwrap();
    let (config, selected) = super::load_config(None, &candidates).unwrap();
    assert_eq!(selected.as_deref(), Some(system.as_path()));
    assert_eq!(config.database, std::path::Path::new("data/system.sqlite3"));
    assert_eq!(config.listen, super::Config::default().listen);
}

#[test]
fn explicit_config_wins_and_missing_explicit_config_never_falls_back() {
    let dir = tempfile::tempdir().unwrap();
    let system = dir.path().join("system.toml");
    let local = dir.path().join("local.toml");
    std::fs::write(&system, "listen = '127.0.0.1:9000'\n").unwrap();
    std::fs::write(
        &local,
        "database = '/usr/local/var/lib/hibiki/hibiki.sqlite3'\n",
    )
    .unwrap();
    let (config, selected) = super::load_config(Some(&local), &[&system]).unwrap();
    assert_eq!(selected.as_deref(), Some(local.as_path()));
    assert_eq!(
        config.database,
        std::path::Path::new("/usr/local/var/lib/hibiki/hibiki.sqlite3")
    );
    std::fs::remove_file(&local).unwrap();
    assert!(super::load_config(Some(&local), &[&system]).is_err());
}

#[test]
fn invalid_or_unreadable_preferred_config_never_falls_back() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("first.toml");
    let second = dir.path().join("second.toml");
    std::fs::write(&second, "").unwrap();
    std::fs::write(&first, "not valid toml").unwrap();
    let error = super::load_config(None, &[&first, &second]).err().unwrap();
    assert!(error.to_string().contains("invalid configuration"));
    std::fs::remove_file(&first).unwrap();
    std::fs::create_dir(&first).unwrap();
    let error = super::load_config(None, &[&first, &second]).err().unwrap();
    assert!(error.to_string().contains("could not read configuration"));
}

pub(crate) async fn invitation_request(
    db: &Database,
    proof: &MembershipProof,
    issuer: &Identity,
    subject: &Identity,
) -> (AdmissionRequest, OneTimeInvitation) {
    let state = proof.verify().unwrap();
    let invitation = OneTimeInvitation::new(
        "wss://example.test/hibiki".into(),
        state.id.clone(),
        state.name.clone(),
        Some((&state, &issuer.device.id())),
    )
    .unwrap();
    db.register_invitation(&issuer.device.id(), invitation.metadata.clone())
        .await
        .unwrap();
    let (_, revision) = db
        .resolve_invitation(&subject.device.id(), invitation.clone())
        .await
        .unwrap();
    let request =
        AdmissionRequest::create(subject, &state, invitation.metadata.id.clone(), revision)
            .unwrap();
    (request, invitation)
}
struct Fixture {
    dir: tempfile::TempDir,
    db: Database,
    a: Identity,
    b: Identity,
    proof: MembershipProof,
}
impl Fixture {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(&dir.path().join("db")).await.unwrap();
        let a = Identity::generate("a".into()).unwrap();
        let b = Identity::generate("b".into()).unwrap();
        db.register(&a.device).await.unwrap();
        db.register(&b.device).await.unwrap();
        let genesis = ChannelGenesis::create(&a, random_id(), "Team".into()).unwrap();
        let proof = db.create(&a.device.id(), genesis).await.unwrap();
        Self {
            dir,
            db,
            a,
            b,
            proof,
        }
    }
    async fn request(&self) -> (AdmissionRequest, OneTimeInvitation) {
        invitation_request(&self.db, &self.proof, &self.a, &self.b).await
    }
    fn event(&self, issuer: &Identity, action: MembershipAction) -> MembershipEvent {
        MembershipEvent::create(issuer, &self.proof.verify().unwrap(), action).unwrap()
    }
    async fn append(&mut self, action: MembershipAction) {
        self.proof = self
            .db
            .append(&self.a.device.id(), self.event(&self.a, action))
            .await
            .unwrap();
    }
    async fn admit(&mut self) -> AdmissionRequest {
        let (request, invite) = self.request().await;
        self.db
            .join(&self.b.device.id(), request.clone(), invite)
            .await
            .unwrap();
        self.append(MembershipAction::Accept(request.clone())).await;
        request
    }
}

#[tokio::test]
async fn admission_requires_key_pending_and_authorized_signature() {
    let mut f = Fixture::new().await;
    let (request, invite) = f.request().await;
    let mut wrong = invite.clone();
    wrong.key[0] ^= 1;
    assert!(
        f.db.join(&f.b.device.id(), request.clone(), wrong)
            .await
            .is_err()
    );
    let event = f.event(&f.a, MembershipAction::Accept(request.clone()));
    assert!(f.db.append(&f.a.device.id(), event.clone()).await.is_err());
    f.db.join(&f.b.device.id(), request.clone(), invite.clone())
        .await
        .unwrap();
    assert!(f.db.append(&f.b.device.id(), event.clone()).await.is_err());
    let mut forged = event.clone();
    forged.signature[0] ^= 1;
    assert!(f.db.append(&f.a.device.id(), forged).await.is_err());
    // Failed approvals roll back their deletion of the pending row.
    assert_eq!(
        f.db.pending(&f.a.device.id(), &f.proof.genesis.body.id)
            .await
            .unwrap(),
        vec![request.clone()]
    );
    f.proof = f.db.append(&f.a.device.id(), event.clone()).await.unwrap();
    assert!(f.db.append(&f.a.device.id(), event).await.is_err());
    f.db.join(&f.b.device.id(), request, invite).await.unwrap(); // lost response retry
    assert!(f.proof.verify().unwrap().member(&f.b.device.id()).is_ok());
}

#[tokio::test]
async fn one_key_has_one_winner_and_retries_survive_restart() {
    let f = Fixture::new().await;
    let (request, invite) = f.request().await;
    let c = Identity::generate("c".into()).unwrap();
    let second = AdmissionRequest::create(
        &c,
        &f.proof.verify().unwrap(),
        invite.metadata.id.clone(),
        0,
    )
    .unwrap();
    let b_id = f.b.device.id();
    let c_id = c.device.id();
    let other = Database::open(&f.dir.path().join("db")).await.unwrap();
    let (one, two) = tokio::join!(
        f.db.join(&b_id, request.clone(), invite.clone()),
        other.join(&c_id, second.clone(), invite.clone())
    );
    assert_ne!(one.is_ok(), two.is_ok());
    let (caller, winner) = if one.is_ok() {
        (&b_id, request)
    } else {
        (&c_id, second)
    };
    other
        .join(caller, winner.clone(), invite.clone())
        .await
        .unwrap();
    assert_eq!(
        other
            .pending(&f.a.device.id(), &f.proof.genesis.body.id)
            .await
            .unwrap(),
        vec![winner.clone()]
    );
    let mut replay = winner.clone();
    replay.body.nonce = random_id();
    let identity = if one.is_ok() { &f.b } else { &c };
    replay.signature = identity.sign("join/v4", &replay.body).unwrap();
    assert!(other.join(caller, replay, invite).await.is_err());
}

#[tokio::test]
async fn committed_admission_retry_survives_inviter_departure_but_not_revocation() {
    let mut f = Fixture::new().await;
    let (request, invite) = f.request().await;
    f.db.join(&f.b.device.id(), request.clone(), invite.clone())
        .await
        .unwrap();
    f.append(MembershipAction::Accept(request.clone())).await;
    f.append(MembershipAction::Leave).await;
    f.db.join(&f.b.device.id(), request.clone(), invite.clone())
        .await
        .unwrap();
    f.db.admin_revoke(&f.proof.genesis.body.id, &f.b.device.id(), false)
        .await
        .unwrap();
    assert!(f.db.join(&f.b.device.id(), request, invite).await.is_err());
}

#[tokio::test]
async fn invitations_are_independent_and_expiry_only_limits_submission() {
    let mut f = Fixture::new().await;
    let (request, mut invite) = f.request().await;
    let (_, second) = f.request().await;
    assert_ne!(invite.key, second.key);
    assert_ne!(invite.metadata.id, second.metadata.id);
    f.db.join(&f.b.device.id(), request.clone(), invite.clone())
        .await
        .unwrap();
    // Advance expiry in the persisted fixture to avoid waiting a day.
    invite.metadata.expires_at = now();
    super::entities::invitation::Entity::update_many()
        .col_expr(
            super::entities::invitation::Column::Metadata,
            sea_orm::sea_query::Expr::value(hibiki_lib::encode(&invite.metadata).unwrap()),
        )
        .filter(super::entities::invitation::Column::Id.eq(&invite.metadata.id))
        .exec(&f.db.connection)
        .await
        .unwrap();
    f.db.join(&f.b.device.id(), request.clone(), invite)
        .await
        .unwrap();
    f.append(MembershipAction::Accept(request)).await;
    let (_, mut expired) = invitation_request(
        &f.db,
        &f.proof,
        &f.a,
        &Identity::generate("d".into()).unwrap(),
    )
    .await;
    expired.metadata.expires_at = now();
    super::entities::invitation::Entity::update_many()
        .col_expr(
            super::entities::invitation::Column::Metadata,
            sea_orm::sea_query::Expr::value(hibiki_lib::encode(&expired.metadata).unwrap()),
        )
        .filter(super::entities::invitation::Column::Id.eq(&expired.metadata.id))
        .exec(&f.db.connection)
        .await
        .unwrap();
    assert!(
        f.db.resolve_invitation(&f.b.device.id(), expired)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn rejected_and_withdrawn_keys_are_not_reusable() {
    let f = Fixture::new().await;
    for withdraw in [false, true] {
        let (request, invite) = f.request().await;
        f.db.join(&f.b.device.id(), request.clone(), invite.clone())
            .await
            .unwrap();
        assert!(
            f.db.remove_pending(
                &f.a.device.id(),
                &request.body.channel_id,
                &request.id().unwrap(),
                true
            )
            .await
            .is_err()
        );
        let caller = if withdraw { &f.b } else { &f.a };
        f.db.remove_pending(
            &caller.device.id(),
            &request.body.channel_id,
            &request.id().unwrap(),
            withdraw,
        )
        .await
        .unwrap();
        assert!(
            f.db.join(&f.b.device.id(), request.clone(), invite)
                .await
                .is_err()
        );
        assert!(
            f.db.append(
                &f.a.device.id(),
                f.event(&f.a, MembershipAction::Accept(request))
            )
            .await
            .is_err()
        );
    }
}

#[tokio::test]
async fn ordinary_revoke_and_leave_allow_fresh_readmission_without_replay() {
    for leave in [false, true] {
        let mut f = Fixture::new().await;
        let original = f.admit().await;
        let first_round = f
            .proof
            .verify()
            .unwrap()
            .admission_id(&f.b.device.id())
            .unwrap()
            .to_owned();
        let event = if leave {
            f.event(&f.b, MembershipAction::Leave)
        } else {
            f.event(
                &f.a,
                MembershipAction::Revoke {
                    device_id: f.b.device.id(),
                },
            )
        };
        let caller = event.body.issuer_device_id.clone();
        f.proof = f.db.append(&caller, event).await.unwrap();
        assert!(
            f.db.append(
                &f.a.device.id(),
                f.event(&f.a, MembershipAction::Accept(original))
            )
            .await
            .is_err()
        );
        let request = f.admit().await;
        assert_ne!(first_round, request.id().unwrap());
        assert!(!f.proof.verify().unwrap().can_revoke_at(
            &f.b.device.id(),
            &f.a.device.id(),
            now() + 29 * 86400
        ));
    }
}

#[tokio::test]
async fn admin_revoked_founder_remains_blocked_until_atomic_readmission() {
    let mut f = Fixture::new().await;
    f.admit().await;
    let id = f.proof.genesis.body.id.clone();
    f.db.admin_revoke(&id, &f.a.device.id(), false)
        .await
        .unwrap();
    assert!(f.db.require_access(&id, &f.a.device.id()).await.is_err());
    let (request, invite) = invitation_request(&f.db, &f.proof, &f.b, &f.a).await;
    f.db.join(&f.a.device.id(), request.clone(), invite)
        .await
        .unwrap();
    assert_eq!(
        f.db.join_status(&f.a.device.id(), &id, &request.id().unwrap())
            .await
            .unwrap(),
        hibiki_lib::protocol::JoinState::Pending
    );
    assert!(f.db.require_access(&id, &f.a.device.id()).await.is_err());
    let event = f.event(&f.b, MembershipAction::Accept(request.clone()));
    f.proof = f.db.append(&f.b.device.id(), event).await.unwrap();
    f.db.require_access(&id, &f.a.device.id()).await.unwrap();
    let state = f.proof.verify().unwrap();
    assert!(state.can_revoke(&f.b.device.id(), &f.a.device.id()));
    assert!(!state.can_revoke(&f.a.device.id(), &f.b.device.id()));
    assert!(state.can_revoke_at(&f.a.device.id(), &f.b.device.id(), now() + 30 * 86400 + 1));
}

#[tokio::test]
async fn repeated_admin_revoke_invalidates_pending_reinstatement() {
    let mut f = Fixture::new().await;
    f.admit().await;
    let id = f.proof.genesis.body.id.clone();
    f.db.admin_revoke(&id, &f.b.device.id(), false)
        .await
        .unwrap();
    let (request, invite) = f.request().await;
    f.db.join(&f.b.device.id(), request.clone(), invite.clone())
        .await
        .unwrap();
    f.db.admin_revoke(&id, &f.b.device.id(), false)
        .await
        .unwrap();
    assert!(
        f.db.append(
            &f.a.device.id(),
            f.event(&f.a, MembershipAction::Accept(request.clone()))
        )
        .await
        .is_err()
    );
    assert!(f.db.join(&f.b.device.id(), request, invite).await.is_err());
    f.admit().await;
    f.db.require_access(&id, &f.b.device.id()).await.unwrap();
}

#[tokio::test]
async fn issuer_departure_invalidates_unused_invitations_and_pending_requests() {
    for admin in [false, true] {
        let mut f = Fixture::new().await;
        f.admit().await;
        let c = Identity::generate("c".into()).unwrap();
        let (request, used) = invitation_request(&f.db, &f.proof, &f.b, &c).await;
        let (_, unused) = invitation_request(&f.db, &f.proof, &f.b, &c).await;
        f.db.join(&c.device.id(), request.clone(), used)
            .await
            .unwrap();
        if admin {
            f.db.admin_revoke(&f.proof.genesis.body.id, &f.b.device.id(), false)
                .await
                .unwrap();
        } else {
            f.append(MembershipAction::Revoke {
                device_id: f.b.device.id(),
            })
            .await;
        }
        assert!(
            f.db.resolve_invitation(&c.device.id(), unused)
                .await
                .is_err()
        );
        assert!(
            f.db.append(
                &f.a.device.id(),
                f.event(&f.a, MembershipAction::Accept(request))
            )
            .await
            .is_err()
        );
    }
}

#[tokio::test]
async fn member_subtree_and_admin_subtree_remove_only_the_selected_branch() {
    for admin in [false, true] {
        let mut f = Fixture::new().await;
        f.admit().await;
        let c = Identity::generate("c".into()).unwrap();
        let (request, invitation) = invitation_request(&f.db, &f.proof, &f.b, &c).await;
        f.db.join(&c.device.id(), request.clone(), invitation)
            .await
            .unwrap();
        f.proof =
            f.db.append(
                &f.b.device.id(),
                f.event(&f.b, MembershipAction::Accept(request)),
            )
            .await
            .unwrap();
        if admin {
            let (_, affected) =
                f.db.admin_revoke(&f.proof.genesis.body.id, &f.b.device.id(), true)
                    .await
                    .unwrap();
            assert_eq!(affected.len(), 2);
            assert!(
                f.db.require_access(&f.proof.genesis.body.id, &c.device.id())
                    .await
                    .is_err()
            );
        } else {
            f.append(MembershipAction::RevokeSubtree {
                device_id: f.b.device.id(),
            })
            .await;
            assert!(f.proof.verify().unwrap().member(&c.device.id()).is_err());
        }
        f.admit().await;
        let state = f.proof.verify().unwrap();
        assert!(!state.can_revoke(&f.b.device.id(), &c.device.id()));
    }
}

#[tokio::test]
async fn concurrent_withdrawal_approval_and_withdraw_all_are_consistent() {
    let mut f = Fixture::new().await;
    for _ in 0..4 {
        let (request, invitation) = f.request().await;
        f.db.join(&f.b.device.id(), request.clone(), invitation)
            .await
            .unwrap();
        let event = f.event(&f.a, MembershipAction::Accept(request.clone()));
        let a = f.a.device.id();
        let b = f.b.device.id();
        let id = f.proof.genesis.body.id.clone();
        let (withdrawn, approved) =
            tokio::join!(f.db.withdraw_pending(&b, &id), f.db.append(&a, event));
        let observed = withdrawn.unwrap().verify().unwrap();
        assert_eq!(observed.member(&b).is_ok(), approved.is_ok());
        f.proof = f.db.get(&id).await.unwrap();
        assert!(f.db.pending(&a, &id).await.unwrap().is_empty());
        if approved.is_ok() {
            f.append(MembershipAction::Revoke { device_id: b }).await;
        }
    }
}

#[tokio::test]
async fn initialization_is_single_use_refreshable_and_delete_cannot_resurrect() {
    let f = Fixture::new().await;
    let old =
        f.db.reserve("wss://example.test/hibiki".into(), "Empty".into())
            .await
            .unwrap();
    let invitation =
        f.db.reserve_invitation("wss://example.test/hibiki".into(), "Empty")
            .await
            .unwrap();
    assert_ne!(old.key, invitation.key);
    let id = invitation.metadata.channel.clone();
    let a = ChannelGenesis::create(&f.a, id.clone(), "Empty".into()).unwrap();
    let b = ChannelGenesis::create(&f.b, id.clone(), "Empty".into()).unwrap();
    let aid = f.a.device.id();
    let bid = f.b.device.id();
    let (one, two) = tokio::join!(
        f.db.claim(&aid, a.clone(), invitation.clone()),
        f.db.claim(&bid, b, old)
    );
    assert_ne!(one.is_ok(), two.is_ok());
    if one.is_ok() {
        f.db.claim(&aid, a.clone(), invitation.clone())
            .await
            .unwrap();
    }
    f.db.delete(&id).await.unwrap();
    assert!(f.db.claim(&aid, a.clone(), invitation).await.is_err());
    assert!(f.db.create(&aid, a).await.is_err());
    assert!(f.db.get(&f.proof.genesis.body.id).await.is_ok());
}
