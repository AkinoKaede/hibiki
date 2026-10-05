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
    let result = hibiki_core::preparation::query(&mut ep, "SERIALNO".into())
        .await
        .unwrap();
    assert!(matches!(
        assuan::parse_response(result.lines.last().unwrap()).unwrap(),
        assuan::Response::Err(assuan::CARD_NOT_PRESENT)
    ));
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

#[tokio::test]
async fn serial_queries_require_usb_or_an_explicit_registered_nfc_demand() {
    for (nfc_enabled, nfc_available) in [(true, true), (true, false), (false, true)] {
        let (_root, client, context, card) = fixture();
        client.provider.cards.lock().unwrap()[0].nfc_enabled = nfc_enabled;
        client.set_nfc_available(nfc_available);
        let mut ep = client
            .provider
            .open(
                client.app.clone(),
                ServiceKind::Scdaemon,
                client.slots.clone(),
                CancellationToken::new(),
                context,
            )
            .await
            .unwrap();
        for command in ["SERIALNO", "SERIALNO --all", "SERIALNO --demand=ABCD"] {
            let result = hibiki_core::preparation::query(&mut ep, command.into())
                .await
                .unwrap();
            assert!(matches!(
                assuan::parse_response(result.lines.last().unwrap()).unwrap(),
                assuan::Response::Err(assuan::CARD_NOT_PRESENT)
            ));
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(20), client.broker.next())
                .await
                .is_err()
        );
        let command: Line = format!("SERIALNO --demand={}", card.serial).as_str().into();
        if nfc_enabled && nfc_available {
            for accept in [true, false] {
                ep.command(command.clone()).await.unwrap();
                let NativeEvent::Prompt { prompt } = next(&client).await else {
                    panic!()
                };
                assert!(matches!(prompt.kind, PromptKind::CardNfc));
                assert_eq!(
                    prompt.description,
                    hibiki_lib::card_prompt::description(&card.serial, "")
                );
                if accept {
                    client.respond(prompt.token, vec![], true).unwrap();
                    assert_eq!(
                        &*ep.next().await.unwrap(),
                        format!("S SERIALNO {}", card.serial).as_bytes()
                    );
                    assert_eq!(&*ep.next().await.unwrap(), b"OK");
                } else {
                    client.cancel_request(prompt.token).unwrap();
                    assert!(matches!(
                        assuan::parse_response(&ep.next().await.unwrap()).unwrap(),
                        assuan::Response::Err(assuan::CANCELED)
                    ));
                }
                assert!(matches!(next(&client).await, NativeEvent::Cancelled { .. }));
            }
            ep.command(command).await.unwrap();
            let NativeEvent::Prompt { prompt } = next(&client).await else {
                panic!()
            };
            ep.close().await;
            assert!(!client.request_is_pending(prompt.token));
        } else {
            let result = hibiki_core::preparation::query(&mut ep, command)
                .await
                .unwrap();
            assert!(matches!(
                assuan::parse_response(result.lines.last().unwrap()).unwrap(),
                assuan::Response::Err(assuan::CARD_NOT_PRESENT)
            ));
            ep.close().await;
        }
    }
}

#[tokio::test]
async fn selected_nfc_is_volatile_optional_and_cleared_when_unavailable() {
    let (root, client, context, card) = fixture();
    let mut registry = crate::registry::Registry {
        cards: client.provider.cards.lock().unwrap().clone(),
        selected: None,
    };
    let mut second = registry.cards[0].clone();
    second.card.serial = "D2760001240103040000000000020000".into();
    registry.cards.push(second.clone());
    client.save_registry(registry).unwrap();
    assert!(client.selected_nfc_card().is_none());
    assert!(client.select_nfc_card(Some("missing".into())).is_err());
    let mut ep = client
        .provider
        .open(
            client.app.clone(),
            ServiceKind::Scdaemon,
            client.slots.clone(),
            CancellationToken::new(),
            context,
        )
        .await
        .unwrap();
    for serial in [
        Some(card.serial.clone()),
        Some(second.card.serial.clone()),
        None,
    ] {
        client.select_nfc_card(serial.clone()).unwrap();
        assert_eq!(client.selected_nfc_card(), serial);
        let result = hibiki_core::preparation::query(&mut ep, "SERIALNO".into())
            .await
            .unwrap();
        assert_eq!(result.success(), serial.is_some());
        if let Some(serial) = serial {
            assert_eq!(&*result.lines[0], format!("S SERIALNO {serial}").as_bytes());
        }
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(20), client.broker.next())
            .await
            .is_err()
    );
    ep.close().await;
    client.select_nfc_card(Some(card.serial.clone())).unwrap();
    client.set_nfc_available(false);
    client.set_nfc_available(true);
    assert!(client.selected_nfc_card().is_none());
    client.select_nfc_card(Some(card.serial.clone())).unwrap();
    client
        .update_card(card.serial.clone(), "USB only".into(), true, false)
        .await
        .unwrap();
    assert!(client.selected_nfc_card().is_none());
    client
        .select_nfc_card(Some(second.card.serial.clone()))
        .unwrap();
    let restored = MobileClient::new(
        root.path().join("mobile").to_string_lossy().into(),
        "wss://example.com/hibiki".into(),
        create_identity("phone".into()).unwrap(),
        false,
    )
    .unwrap();
    restored.set_nfc_available(true);
    assert_eq!(restored.registered_cards().len(), 2);
    assert!(restored.selected_nfc_card().is_none());
    client.remove_card(second.card.serial).await.unwrap();
    assert!(client.selected_nfc_card().is_none());
}
