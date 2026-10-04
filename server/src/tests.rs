use super::{db::Database, service::Service};
use hibiki_lib::{channel::*, digest, identity::Identity, now};

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

struct Fixture {
    _dir: tempfile::TempDir,
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
        let verifier = hash_psk("test-secret").unwrap();
        let genesis = ChannelGenesis::create(&a, "Team".into(), &verifier).unwrap();
        let proof = db.create(&a.device.id(), genesis, verifier).await.unwrap();
        Self {
            _dir: dir,
            db,
            a,
            b,
            proof,
        }
    }
    fn request(&self) -> JoinRequest {
        JoinRequest::create(&self.b, &self.proof.verify().unwrap()).unwrap()
    }
    async fn admit(&mut self) {
        let request = self.request();
        self.db
            .join(&self.b.device.id(), request.clone(), "test-secret".into())
            .await
            .unwrap();
        let event = MembershipEvent::create(
            &self.a,
            &self.proof.verify().unwrap(),
            MembershipAction::Admit(request),
        )
        .unwrap();
        self.proof = self
            .db
            .append(&self.a.device.id(), event, None)
            .await
            .unwrap();
    }
}
#[tokio::test]
async fn admission_requires_psk_pending_and_one_authorized_signature() {
    let mut f = Fixture::new().await;
    let request = f.request();
    assert!(
        f.db.join(&f.b.device.id(), request.clone(), "wrong".into())
            .await
            .is_err()
    );
    assert!(
        f.db.pending(&f.b.device.id(), &f.proof.genesis.body.id)
            .await
            .is_err()
    );
    let event = MembershipEvent::create(
        &f.a,
        &f.proof.verify().unwrap(),
        MembershipAction::Admit(request.clone()),
    )
    .unwrap();
    assert!(
        f.db.append(&f.a.device.id(), event.clone(), None)
            .await
            .is_err()
    );
    f.db.join(&f.b.device.id(), request, "test-secret".into())
        .await
        .unwrap();
    assert!(
        f.db.append(&f.b.device.id(), event.clone(), None)
            .await
            .is_err()
    );
    let mut forged = event.clone();
    forged.signature[0] ^= 1;
    assert!(f.db.append(&f.a.device.id(), forged, None).await.is_err());
    f.proof =
        f.db.append(&f.a.device.id(), event.clone(), None)
            .await
            .unwrap();
    assert!(f.proof.verify().unwrap().member(&f.b.device.id()).is_ok());
    assert!(f.db.append(&f.a.device.id(), event, None).await.is_err());
    assert!(
        f.db.pending(&f.a.device.id(), &f.proof.genesis.body.id)
            .await
            .unwrap()
            .is_empty()
    );
}
#[tokio::test]
async fn pending_requests_do_not_expire_and_approval_is_atomic() {
    let f = Fixture::new().await;
    let mut request = f.request();
    request.body.created_at = now() - 86400;
    request.signature = f.b.sign("join/v1", &request.body).unwrap();
    assert!(
        f.db.join(&f.b.device.id(), request.clone(), "test-secret".into())
            .await
            .is_ok()
    );
    f.db.join(&f.b.device.id(), request.clone(), "test-secret".into())
        .await
        .unwrap();
    let reopened = Database::open(&f._dir.path().join("db")).await.unwrap();
    assert_eq!(
        reopened
            .pending(&f.a.device.id(), &f.proof.genesis.body.id)
            .await
            .unwrap(),
        vec![request.clone()]
    );
    let event = MembershipEvent::create(
        &f.a,
        &f.proof.verify().unwrap(),
        MembershipAction::Admit(request),
    )
    .unwrap();
    let caller = f.a.device.id();
    let (a, b) = tokio::join!(
        f.db.append(&caller, event.clone(), None),
        f.db.append(&caller, event, None)
    );
    assert_ne!(a.is_ok(), b.is_ok());
    assert_eq!(
        f.db.get(&f.proof.genesis.body.id)
            .await
            .unwrap()
            .verify()
            .unwrap()
            .sequence,
        1
    );
}
#[tokio::test]
async fn any_member_rotates_and_revokes_and_old_requests_cannot_return() {
    let mut f = Fixture::new().await;
    f.admit().await;
    let c = Identity::generate("c".into()).unwrap();
    let stale = JoinRequest::create(&c, &f.proof.verify().unwrap()).unwrap();
    f.db.join(&c.device.id(), stale.clone(), "test-secret".into())
        .await
        .unwrap();
    let verifier = hash_psk("replacement-secret").unwrap();
    let rotate = MembershipEvent::create(
        &f.b,
        &f.proof.verify().unwrap(),
        MembershipAction::ChangePsk {
            verifier_commitment: digest(verifier.as_bytes()),
        },
    )
    .unwrap();
    f.proof =
        f.db.append(&f.b.device.id(), rotate, Some(verifier))
            .await
            .unwrap();
    let state = f.proof.verify().unwrap();
    assert!(state.member(&f.a.device.id()).is_ok());
    assert!(state.member(&f.b.device.id()).is_ok());
    assert!(
        f.db.pending(&f.a.device.id(), &state.id)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        f.db.join(&c.device.id(), stale.clone(), "replacement-secret".into())
            .await
            .is_err()
    );
    let invalid = MembershipEvent::create(&f.a, &state, MembershipAction::Admit(stale)).unwrap();
    assert!(f.db.append(&f.a.device.id(), invalid, None).await.is_err());
    let fresh = JoinRequest::create(&c, &state).unwrap();
    assert!(
        f.db.join(&c.device.id(), fresh.clone(), "test-secret".into())
            .await
            .is_err()
    );
    f.db.join(&c.device.id(), fresh, "replacement-secret".into())
        .await
        .unwrap();
    let revoke = MembershipEvent::create(
        &f.b,
        &state,
        MembershipAction::Revoke {
            device_id: f.a.device.id(),
        },
    )
    .unwrap();
    f.proof = f.db.append(&f.b.device.id(), revoke, None).await.unwrap();
    assert!(f.db.pending(&f.a.device.id(), &state.id).await.is_err());
    assert!(
        f.db.get(&state.id)
            .await
            .unwrap()
            .verify()
            .unwrap()
            .member(&f.a.device.id())
            .is_err()
    );
}
#[tokio::test]
async fn persistence_and_identity_binding_are_pinned() {
    let mut f = Fixture::new().await;
    f.admit().await;
    let reopened = Database::open(&f._dir.path().join("db")).await.unwrap();
    assert_eq!(
        reopened.get(&f.proof.genesis.body.id).await.unwrap(),
        f.proof
    );
    let mut changed = f.a.device.clone();
    changed.noise_key[0] ^= 1;
    assert!(reopened.register(&changed).await.is_err());
    let _ = Service::new(reopened, true);
}

#[tokio::test]
async fn empty_channel_claim_requires_psk_and_has_exactly_one_founder() {
    let f = Fixture::new().await;
    let verifier = hash_psk("empty-secret").unwrap();
    let invitation =
        f.db.reserve(
            "wss://example.test/hibiki".into(),
            "Empty".into(),
            verifier.clone(),
        )
        .await
        .unwrap();
    assert!(
        f.db.admin_list()
            .await
            .unwrap()
            .iter()
            .any(|(id, _, empty)| id == &invitation.id && *empty)
    );
    assert!(f.db.get(&invitation.id).await.is_err());
    assert!(
        f.db.reserve(
            invitation.server.clone(),
            invitation.name.clone(),
            verifier.clone()
        )
        .await
        .is_err()
    );
    let ga = invitation.founder_genesis(&f.a).unwrap();
    let gb = invitation.founder_genesis(&f.b).unwrap();
    // Neither a remote Create nor a forged founder may steal the reservation.
    assert!(
        f.db.create(&f.a.device.id(), ga.clone(), verifier.clone())
            .await
            .is_err()
    );
    assert!(
        f.db.claim(&f.b.device.id(), ga.clone(), "empty-secret".into())
            .await
            .is_err()
    );
    assert!(
        f.db.claim(&f.a.device.id(), ga.clone(), "wrong-psk".into())
            .await
            .is_err()
    );
    let mut altered = invitation.clone();
    altered.name = "Substituted".into();
    assert!(
        f.db.claim(
            &f.a.device.id(),
            altered.founder_genesis(&f.a).unwrap(),
            "empty-secret".into()
        )
        .await
        .is_err()
    );
    let aid = f.a.device.id();
    let bid = f.b.device.id();
    let (a, b) = tokio::join!(
        f.db.claim(&aid, ga, "empty-secret".into()),
        f.db.claim(&bid, gb, "empty-secret".into())
    );
    assert_ne!(a.is_ok(), b.is_ok());
    let proof = f.db.get(&invitation.id).await.unwrap();
    assert_eq!(proof.verify().unwrap().members().len(), 1);
    assert!(
        f.db.claim(
            &aid,
            invitation.founder_genesis(&f.a).unwrap(),
            "empty-secret".into()
        )
        .await
        .is_err()
    );
    assert!(
        !f.db
            .admin_list()
            .await
            .unwrap()
            .iter()
            .find(|(id, _, _)| id == &invitation.id)
            .unwrap()
            .2
    );
    let (founder, newcomer) = if a.is_ok() {
        (&f.a, &f.b)
    } else {
        (&f.b, &f.a)
    };
    let request = JoinRequest::create(newcomer, &proof.verify().unwrap()).unwrap();
    f.db.join(
        &newcomer.device.id(),
        request.clone(),
        "empty-secret".into(),
    )
    .await
    .unwrap();
    assert_eq!(
        f.db.get(&invitation.id)
            .await
            .unwrap()
            .verify()
            .unwrap()
            .members()
            .len(),
        1
    );
    let approve = MembershipEvent::create(
        founder,
        &proof.verify().unwrap(),
        MembershipAction::Admit(request),
    )
    .unwrap();
    assert_eq!(
        f.db.append(&founder.device.id(), approve, None)
            .await
            .unwrap()
            .verify()
            .unwrap()
            .members()
            .len(),
        2
    );
}

#[tokio::test]
async fn delete_cleans_pending_preserves_other_channels_and_never_reuses_id() {
    use crate::entities::pending;
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
    let f = Fixture::new().await;
    let verifier = hash_psk("test-secret").unwrap();
    let invitation =
        f.db.reserve(
            "ws://localhost/hibiki".into(),
            "Empty".into(),
            verifier.clone(),
        )
        .await
        .unwrap();
    assert_eq!(f.db.delete("Empty").await.unwrap(), invitation.id);
    assert!(
        f.db.claim(
            &f.a.device.id(),
            invitation.founder_genesis(&f.a).unwrap(),
            "test-secret".into()
        )
        .await
        .is_err()
    );
    let pending_request = f.request();
    f.db.join(&f.b.device.id(), pending_request, "test-secret".into())
        .await
        .unwrap();
    let replacement =
        f.db.reserve(
            "ws://localhost/hibiki".into(),
            "Empty".into(),
            verifier.clone(),
        )
        .await
        .unwrap();
    assert_ne!(replacement.id, invitation.id);
    assert_eq!(f.db.delete("Team").await.unwrap(), f.proof.genesis.body.id);
    assert!(f.db.get(&f.proof.genesis.body.id).await.is_err());
    assert!(
        f.db.admin_list()
            .await
            .unwrap()
            .iter()
            .any(|(id, _, _)| id == &replacement.id)
    );
    assert!(
        f.db.create(&f.a.device.id(), f.proof.genesis.clone(), verifier.clone())
            .await
            .is_err()
    );
    assert!(f.db.delete("Team").await.is_err());
    let connection = sea_orm::Database::connect(format!(
        "sqlite:{}?mode=rw",
        f._dir.path().join("db").display()
    ))
    .await
    .unwrap();
    assert!(
        pending::Entity::find()
            .filter(pending::Column::Channel.eq(&f.proof.genesis.body.id))
            .all(&connection)
            .await
            .unwrap()
            .is_empty()
    );
    let restored_name =
        f.db.reserve("ws://localhost/hibiki".into(), "Team".into(), verifier)
            .await
            .unwrap();
    assert_ne!(restored_name.id, f.proof.genesis.body.id);
}

#[tokio::test]
async fn concurrent_claim_and_delete_never_resurrects_a_channel() {
    let f = Fixture::new().await;
    let invite =
        f.db.reserve(
            "ws://localhost/hibiki".into(),
            "Race".into(),
            hash_psk("race-secret").unwrap(),
        )
        .await
        .unwrap();
    let caller = f.a.device.id();
    let (claimed, removed) = tokio::join!(
        f.db.claim(
            &caller,
            invite.founder_genesis(&f.a).unwrap(),
            "race-secret".into()
        ),
        f.db.delete("Race")
    );
    assert_eq!(removed.unwrap(), invite.id);
    if let Ok(proof) = claimed {
        assert_eq!(proof.genesis.body.id, invite.id);
    }
    assert!(!f.db.exists(&invite.id).await.unwrap());
    assert!(
        !f.db
            .admin_list()
            .await
            .unwrap()
            .iter()
            .any(|(id, _, _)| id == &invite.id)
    );
    assert!(
        f.db.claim(
            &caller,
            invite.founder_genesis(&f.a).unwrap(),
            "race-secret".into()
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn member_can_leave_and_rejoin_only_after_new_approval() {
    let mut f = Fixture::new().await;
    f.admit().await;
    let leave =
        MembershipEvent::create(&f.b, &f.proof.verify().unwrap(), MembershipAction::Leave).unwrap();
    assert!(
        f.db.append(&f.a.device.id(), leave.clone(), None)
            .await
            .is_err()
    );
    f.proof =
        f.db.append(&f.b.device.id(), leave.clone(), None)
            .await
            .unwrap();
    assert!(f.proof.verify().unwrap().member(&f.b.device.id()).is_err());
    assert!(f.db.append(&f.b.device.id(), leave, None).await.is_err());
    assert!(
        f.db.pending(&f.b.device.id(), &f.proof.genesis.body.id)
            .await
            .is_err()
    );
    f.admit().await;
    assert!(f.proof.verify().unwrap().member(&f.b.device.id()).is_ok());
    // An empty membership after voluntary departure is not a new unclaimed reservation.
    for identity in [&f.b, &f.a] {
        let leave = MembershipEvent::create(
            identity,
            &f.proof.verify().unwrap(),
            MembershipAction::Leave,
        )
        .unwrap();
        f.proof =
            f.db.append(&identity.device.id(), leave, None)
                .await
                .unwrap();
    }
    assert!(f.proof.verify().unwrap().members().is_empty());
    assert!(
        f.db.claim(
            &f.a.device.id(),
            f.proof.genesis.clone(),
            "test-secret".into()
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn pending_removal_checks_ownership_and_blocks_stale_approval() {
    use hibiki_lib::protocol::JoinState;
    let f = Fixture::new().await;
    let request = f.request();
    let id = request.id().unwrap();
    let channel = &f.proof.genesis.body.id;
    let outsider = Identity::generate("outsider".into()).unwrap();
    f.db.join(&f.b.device.id(), request.clone(), "test-secret".into())
        .await
        .unwrap();
    assert_eq!(
        f.db.join_status(&f.b.device.id(), channel, &id)
            .await
            .unwrap(),
        JoinState::Pending
    );
    assert!(
        f.db.remove_pending(&outsider.device.id(), channel, &id, false)
            .await
            .is_err()
    );
    assert!(
        f.db.remove_pending(&outsider.device.id(), channel, &id, true)
            .await
            .is_err()
    );
    assert!(
        f.db.remove_pending(&f.a.device.id(), channel, &id, true)
            .await
            .is_err()
    );
    assert!(
        f.db.join_status(&outsider.device.id(), channel, &id)
            .await
            .is_err()
    );
    let event = MembershipEvent::create(
        &f.a,
        &f.proof.verify().unwrap(),
        MembershipAction::Admit(request.clone()),
    )
    .unwrap();
    f.db.remove_pending(&f.b.device.id(), channel, &id, true)
        .await
        .unwrap();
    assert_eq!(
        f.db.join_status(&f.b.device.id(), channel, &id)
            .await
            .unwrap(),
        JoinState::Absent
    );
    assert!(
        f.db.append(&f.a.device.id(), event.clone(), None)
            .await
            .is_err()
    );
    assert!(
        f.db.get(channel)
            .await
            .unwrap()
            .verify()
            .unwrap()
            .member(&f.b.device.id())
            .is_err()
    );
    f.db.join(&f.b.device.id(), request, "test-secret".into())
        .await
        .unwrap();
    f.db.remove_pending(&f.a.device.id(), channel, &id, false)
        .await
        .unwrap();
    assert!(f.db.append(&f.a.device.id(), event, None).await.is_err());
    assert!(
        f.db.pending(&f.a.device.id(), channel)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn concurrent_withdrawal_and_approval_have_only_one_winner() {
    let f = Fixture::new().await;
    let request = f.request();
    let id = request.id().unwrap();
    let channel = &f.proof.genesis.body.id;
    f.db.join(&f.b.device.id(), request.clone(), "test-secret".into())
        .await
        .unwrap();
    let event = MembershipEvent::create(
        &f.a,
        &f.proof.verify().unwrap(),
        MembershipAction::Admit(request),
    )
    .unwrap();
    let other = Database::open(&f._dir.path().join("db")).await.unwrap();
    let a = f.a.device.id();
    let b = f.b.device.id();
    let (approved, withdrawn) = tokio::join!(
        f.db.append(&a, event, None),
        other.remove_pending(&b, channel, &id, true),
    );
    assert_ne!(approved.is_ok(), withdrawn.is_ok());
    let state = f.db.get(channel).await.unwrap().verify().unwrap();
    assert_eq!(state.member(&b).is_ok(), approved.is_ok());
    assert!(f.db.pending(&a, channel).await.unwrap().is_empty());
}

#[tokio::test]
async fn withdraw_all_is_scoped_to_device_and_channel_and_blocks_old_requests() {
    let f = Fixture::new().await;
    let channel = &f.proof.genesis.body.id;
    let a = f.a.device.id();
    let b = f.b.device.id();
    let outsider = Identity::generate("outsider".into()).unwrap();
    let requests = [f.request(), f.request()];
    for request in &requests {
        f.db.join(&b, request.clone(), "test-secret".into())
            .await
            .unwrap();
    }
    let other_request = JoinRequest::create(&outsider, &f.proof.verify().unwrap()).unwrap();
    f.db.join(
        &outsider.device.id(),
        other_request.clone(),
        "test-secret".into(),
    )
    .await
    .unwrap();
    let verifier = hash_psk("test-secret").unwrap();
    let other_channel =
        f.db.create(
            &a,
            ChannelGenesis::create(&f.a, "Other".into(), &verifier).unwrap(),
            verifier,
        )
        .await
        .unwrap();
    let other_channel_request =
        JoinRequest::create(&f.b, &other_channel.verify().unwrap()).unwrap();
    f.db.join(&b, other_channel_request.clone(), "test-secret".into())
        .await
        .unwrap();

    // A member with no own pending requests cannot remove anyone else's.
    assert_eq!(f.db.withdraw_pending(&a, channel).await.unwrap(), f.proof);
    assert_eq!(f.db.pending(&a, channel).await.unwrap().len(), 3);
    assert_eq!(f.db.withdraw_pending(&b, channel).await.unwrap(), f.proof);
    assert_eq!(
        f.db.pending(&a, channel).await.unwrap(),
        vec![other_request]
    );
    assert_eq!(
        f.db.pending(&a, &other_channel.genesis.body.id)
            .await
            .unwrap(),
        vec![other_channel_request]
    );
    for request in requests {
        let event = MembershipEvent::create(
            &f.a,
            &f.proof.verify().unwrap(),
            MembershipAction::Admit(request),
        )
        .unwrap();
        assert!(f.db.append(&a, event, None).await.is_err());
    }
    assert_eq!(f.db.withdraw_pending(&b, channel).await.unwrap(), f.proof);
}

#[tokio::test]
async fn withdraw_all_after_approval_returns_membership_and_cancels_remaining_requests() {
    let f = Fixture::new().await;
    let channel = &f.proof.genesis.body.id;
    let a = f.a.device.id();
    let b = f.b.device.id();
    let requests = [f.request(), f.request()];
    for request in &requests {
        f.db.join(&b, request.clone(), "test-secret".into())
            .await
            .unwrap();
    }
    let approval = MembershipEvent::create(
        &f.a,
        &f.proof.verify().unwrap(),
        MembershipAction::Admit(requests[0].clone()),
    )
    .unwrap();
    f.db.append(&a, approval, None).await.unwrap();
    let proof = f.db.withdraw_pending(&b, channel).await.unwrap();
    assert!(proof.verify().unwrap().member(&b).is_ok());
    let departure =
        MembershipEvent::create(&f.b, &proof.verify().unwrap(), MembershipAction::Leave).unwrap();
    let proof = f.db.append(&b, departure, None).await.unwrap();
    assert!(proof.verify().unwrap().member(&b).is_err());
    let stale = MembershipEvent::create(
        &f.a,
        &proof.verify().unwrap(),
        MembershipAction::Admit(requests[1].clone()),
    )
    .unwrap();
    assert!(f.db.append(&a, stale, None).await.is_err());
    assert!(f.db.pending(&a, channel).await.unwrap().is_empty());
}

#[tokio::test]
async fn withdraw_all_racing_approval_returns_a_consistent_membership_snapshot() {
    let f = Fixture::new().await;
    let channel = &f.proof.genesis.body.id;
    let a = f.a.device.id();
    let b = f.b.device.id();
    let request = f.request();
    f.db.join(&b, request.clone(), "test-secret".into())
        .await
        .unwrap();
    let event = MembershipEvent::create(
        &f.a,
        &f.proof.verify().unwrap(),
        MembershipAction::Admit(request),
    )
    .unwrap();
    let other = Database::open(&f._dir.path().join("db")).await.unwrap();
    let (approved, withdrawn) = tokio::join!(
        f.db.append(&a, event, None),
        other.withdraw_pending(&b, channel),
    );
    let proof = match withdrawn {
        Ok(proof) => proof,
        Err(error) => {
            assert!(error.to_string().contains("CONFLICT"));
            other.withdraw_pending(&b, channel).await.unwrap()
        }
    };
    assert_eq!(proof.verify().unwrap().member(&b).is_ok(), approved.is_ok());
    assert!(f.db.pending(&a, channel).await.unwrap().is_empty());
}
