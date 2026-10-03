use super::{db::Database, service::Service};
use hibiki_lib::{channel::*, digest, identity::Identity, now};

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
async fn expiry_and_concurrent_approval_are_atomic() {
    let f = Fixture::new().await;
    let mut expired = f.request();
    expired.body.created_at = now() - 601;
    expired.body.expires_at = now() - 1;
    expired.signature = f.b.sign("join/v1", &expired.body).unwrap();
    assert!(
        f.db.join(&f.b.device.id(), expired, "test-secret".into())
            .await
            .is_err()
    );
    let request = f.request();
    f.db.join(&f.b.device.id(), request.clone(), "test-secret".into())
        .await
        .unwrap();
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
async fn seaorm_opens_legacy_database_without_changing_signed_records() {
    use sea_orm::{ConnectionTrait, DbBackend, Statement};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("legacy.sqlite");
    let connection = sea_orm::Database::connect(format!("sqlite:{}?mode=rwc", path.display()))
        .await
        .unwrap();
    for sql in [
        "CREATE TABLE devices (id TEXT PRIMARY KEY, bundle BLOB NOT NULL)",
        "CREATE TABLE channels (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, proof BLOB NOT NULL, head BLOB NOT NULL, verifier TEXT NOT NULL)",
        "CREATE TABLE pending (id TEXT PRIMARY KEY, channel TEXT NOT NULL REFERENCES channels(id), request BLOB NOT NULL, expires INTEGER NOT NULL, epoch INTEGER NOT NULL)",
    ] {
        connection.execute_unprepared(sql).await.unwrap();
    }
    let identity = Identity::generate("legacy".into()).unwrap();
    let verifier = hash_psk("test-secret").unwrap();
    let proof = MembershipProof {
        genesis: ChannelGenesis::create(&identity, "Legacy".into(), &verifier).unwrap(),
        events: vec![],
    };
    let bytes = hibiki_lib::encode(&proof).unwrap();
    connection
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "INSERT INTO channels(id,name,proof,head,verifier) VALUES(?,?,?,?,?)",
            [
                proof.genesis.body.id.clone().into(),
                "Legacy".into(),
                bytes.clone().into(),
                proof.genesis.hash().unwrap().to_vec().into(),
                verifier.clone().into(),
            ],
        ))
        .await
        .unwrap();
    connection.close().await.unwrap();
    let db = Database::open(&path).await.unwrap();
    assert_eq!(
        hibiki_lib::encode(&db.get(&proof.genesis.body.id).await.unwrap()).unwrap(),
        bytes
    );
    assert_eq!(
        db.admin_list().await.unwrap(),
        vec![(proof.genesis.body.id.clone(), "Legacy".into(), false)]
    );
    assert!(
        db.reserve("ws://localhost/hibiki".into(), "Legacy".into(), verifier)
            .await
            .is_err()
    );
    assert_eq!(
        Database::open(&path)
            .await
            .unwrap()
            .get(&proof.genesis.body.id)
            .await
            .unwrap(),
        proof
    );
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
