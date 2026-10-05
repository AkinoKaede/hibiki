use super::*;
use crate::*;
use hibiki_core::{
    endpoint::Endpoint,
    provider::{Preparation, Provider, ProviderContext},
};
use hibiki_lib::{
    assuan,
    channel::{ChannelGenesis, MembershipProof},
    protocol::{CardTarget, ServiceKind},
};

fn fixture() -> (
    tempfile::TempDir,
    Arc<MobileClient>,
    ProviderContext,
    CardInfo,
) {
    let root = tempfile::tempdir().unwrap();
    let client = MobileClient::new(
        root.path().join("mobile").to_string_lossy().into(),
        "wss://example.com/hibiki".into(),
        create_identity("phone".into()).unwrap(),
        false,
    )
    .unwrap();
    let genesis = ChannelGenesis::create(&client.app.identity, "test".into(), "verifier").unwrap();
    let context = ProviderContext {
        local: None,
        channel: genesis.body.id.clone(),
        peer: client.app.identity.device.id(),
        session: "cancel-test".into(),
    };
    client
        .app
        .bootstrap(
            MembershipProof {
                genesis,
                events: vec![],
            },
            None,
        )
        .unwrap();
    client.set_services(true, true);
    client.set_nfc_available(true);
    let card = CardInfo {
        serial: "D2760001240103040000000000010000".into(),
        transport: CardTransport::Nfc,
        keys: vec![CardKey {
            slot: 1,
            algorithm: "rsa".into(),
            fingerprint: "11".repeat(20),
            keygrip: "22".repeat(20),
            public_key: vec![],
            created_at: 0,
        }],
    };
    client.provider.cards.lock().unwrap().push(RegisteredCard {
        card: card.clone(),
        name: "test".into(),
        usb_enabled: true,
        nfc_enabled: true,
    });
    (root, client, context, card)
}
async fn next(client: &MobileClient) -> NativeEvent {
    tokio::time::timeout(Duration::from_secs(2), client.broker.next())
        .await
        .unwrap()
        .unwrap()
}

async fn prepare(
    client: &MobileClient,
    context: ProviderContext,
) -> (Box<dyn Preparation>, Endpoint) {
    let ep = client
        .provider
        .open(
            client.app.clone(),
            ServiceKind::Scdaemon,
            client.slots.clone(),
            CancellationToken::new(),
            context.clone(),
        )
        .await
        .unwrap();
    let preparation = client
        .provider
        .prepare(client.app.clone(), CardTarget::default(), context)
        .unwrap();
    (preparation, ep)
}

#[tokio::test]
async fn no_card_cancel_is_retained_while_preparation_is_paused_for_a_public_query() {
    let (_root, client, context, _) = fixture();
    let (mut preparation, mut ep) = prepare(&client, context).await;
    let pause = CancellationToken::new();
    let token = pause.clone();
    let task = tokio::spawn(async move {
        let result = preparation.poll(&mut ep, token).await;
        (preparation, ep, result)
    });
    let NativeEvent::Prompt { prompt } = next(&client).await else {
        panic!()
    };
    pause.cancel();
    let (mut preparation, mut ep, result) = task.await.unwrap();
    assert!(result.unwrap().is_none());
    client.cancel_request(prompt.token.clone()).unwrap();
    assert!(
        hibiki_core::preparation::query(&mut ep, "SERIALNO".into())
            .await
            .unwrap()
            .success()
    );
    let error = tokio::time::timeout(
        Duration::from_secs(1),
        preparation.poll(&mut ep, CancellationToken::new()),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert!(error.is::<hibiki_core::provider::PreparationRejected>());
    assert!(!client.request_is_pending(prompt.token));
    ep.close().await;
}

#[tokio::test]
async fn preparation_cancel_interrupts_pending_usb_probe() {
    let (_root, client, context, _) = fixture();
    let (mut preparation, mut ep) = prepare(&client, context).await;
    let task =
        tokio::spawn(async move { preparation.poll(&mut ep, CancellationToken::new()).await });
    let NativeEvent::Prompt { prompt } = next(&client).await else {
        panic!()
    };
    client.usb_present(true);
    let NativeEvent::CardOpen {
        token, connection, ..
    } = next(&client).await
    else {
        panic!()
    };
    // Leave the hardware request unanswered, as with a stalled reader.
    client.cancel_request(prompt.token).unwrap();
    let error = tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(error.is::<hibiki_core::provider::PreparationRejected>());
    loop {
        if let NativeEvent::CardClose { connection: closed } = next(&client).await {
            assert_eq!(closed, connection);
            break;
        }
    }
    assert!(!client.request_is_pending(token.clone()));
    assert!(client.respond(token, vec![], true).is_err());
}

#[tokio::test]
async fn private_operation_preserves_native_cancellation_at_open_and_transmit() {
    for transport in [CardTransport::Nfc, CardTransport::Usb] {
        for transmit in [false, true] {
            let (_root, client, context, mut card) = fixture();
            card.transport = transport.clone();
            client.usb_present(transport == CardTransport::Usb);
            let mut ep = client
                .provider
                .open(
                    client.app.clone(),
                    ServiceKind::Scdaemon,
                    client.slots.clone(),
                    CancellationToken::new(),
                    context.clone(),
                )
                .await
                .unwrap();
            // Bind the same prepared card that the acquisition controller would supply.
            *client.provider.sessions.lock().unwrap()[&context.session]
                .upgrade()
                .unwrap()
                .lock()
                .unwrap() = Some(card);
            ep.command("SETDATA 01".into()).await.unwrap();
            assert_eq!(&*ep.next().await.unwrap(), b"OK");
            ep.command("PKSIGN --hash=sha256 OPENPGP.1".into())
                .await
                .unwrap();
            if transport == CardTransport::Nfc {
                assert!(ep.next().await.unwrap().starts_with(b"INQUIRE NEEDPIN"));
                ep.answer("D 123456".into()).await.unwrap();
                ep.answer("END".into()).await.unwrap();
            }
            let NativeEvent::CardOpen { mut token, .. } = next(&client).await else {
                panic!()
            };
            if transmit {
                client.respond(token, vec![], true).unwrap();
                token = loop {
                    if let NativeEvent::CardTransmit { token, .. } = next(&client).await {
                        break token;
                    }
                };
            }
            client
                .fail_native_request(token, "user canceled".into(), true)
                .unwrap();
            let line = tokio::time::timeout(Duration::from_secs(1), ep.next())
                .await
                .unwrap()
                .unwrap();
            assert!(
                matches!(
                    assuan::parse_response(&line).unwrap(),
                    assuan::Response::Err(assuan::CANCELED)
                ),
                "{line:?}"
            );
            ep.close().await;
        }
    }
}
