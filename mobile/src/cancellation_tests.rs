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
        .prepare(
            client.app.clone(),
            CardTarget {
                serial: Some("D2760001240103040000000000010000".into()),
                key: None,
            },
            context,
        )
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
async fn private_operation_stops_on_native_cancellation_or_fault_without_fallback() {
    for transport in [CardTransport::Nfc, CardTransport::Usb] {
        for (transmit, canceled) in [(false, false), (false, true), (true, false), (true, true)] {
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
            client.provider.sessions.lock().unwrap()[&context.session]
                .upgrade()
                .unwrap()
                .lock()
                .unwrap()
                .prepared = Some(card);
            ep.command("SETDATA 01".into()).await.unwrap();
            assert_eq!(&*ep.next().await.unwrap(), b"OK");
            ep.command("PKSIGN --hash=sha256 OPENPGP.1".into())
                .await
                .unwrap();
            assert!(ep.next().await.unwrap().starts_with(b"INQUIRE NEEDPIN"));
            assert!(
                tokio::time::timeout(Duration::from_millis(20), client.next_event())
                    .await
                    .is_err()
            );
            ep.answer("D 123456".into()).await.unwrap();
            ep.answer("END".into()).await.unwrap();
            let NativeEvent::CardOpen {
                mut token,
                transport: actual,
                ..
            } = next(&client).await
            else {
                panic!()
            };
            assert_eq!(actual, CardTransport::Usb);
            if transport == CardTransport::Nfc {
                client.card_not_present(token).unwrap();
                token = loop {
                    if let NativeEvent::CardOpen {
                        token, transport, ..
                    } = next(&client).await
                    {
                        assert_eq!(transport, CardTransport::Nfc);
                        break token;
                    }
                };
            }
            if transmit {
                client.respond(token, vec![], true).unwrap();
                token = loop {
                    if let NativeEvent::CardTransmit { token, .. } = next(&client).await {
                        break token;
                    }
                };
            }
            client
                .fail_native_request(token, "reader error".into(), canceled)
                .unwrap();
            let line = tokio::time::timeout(Duration::from_secs(1), ep.next())
                .await
                .unwrap()
                .unwrap();
            assert!(
                matches!(
                    assuan::parse_response(&line).unwrap(),
                    assuan::Response::Err(code) if code == if canceled { assuan::CANCELED } else { assuan::GENERAL }
                ),
                "{line:?}"
            );
            ep.close().await;
        }
    }
}

#[tokio::test]
async fn serial_queries_use_only_the_current_volatile_record_without_prompting() {
    for (recorded, available) in [(true, true), (true, false), (false, true)] {
        let (_root, client, context, card) = fixture();
        if recorded {
            *client.provider.nfc_card.lock().unwrap() = Some(card.clone());
        }
        client.set_nfc_available(available);
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
        for command in [
            "SERIALNO".to_owned(),
            "SERIALNO --all".into(),
            format!("SERIALNO --demand={}", card.serial),
        ] {
            let result = hibiki_core::preparation::query(&mut ep, command.as_str().into())
                .await
                .unwrap();
            assert_eq!(result.success(), recorded && available);
        }
        let result = hibiki_core::preparation::query(&mut ep, "SERIALNO --demand=ABCD".into())
            .await
            .unwrap();
        assert!(!result.success());
        assert!(
            tokio::time::timeout(Duration::from_millis(20), client.next_event())
                .await
                .is_err()
        );
        ep.close().await;
    }
}

#[tokio::test]
async fn recorded_nfc_prepares_without_prompt_and_clear_cancels_dependent_session() {
    let (_root, client, context, card) = fixture();
    *client.provider.nfc_card.lock().unwrap() = Some(card.clone());
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
    let mut preparation = client
        .provider
        .prepare(
            client.app.clone(),
            CardTarget {
                serial: Some(card.serial.clone()),
                key: Some(card.keys[0].keygrip.clone()),
            },
            context.clone(),
        )
        .unwrap();
    assert_eq!(
        preparation
            .poll(&mut ep, CancellationToken::new())
            .await
            .unwrap(),
        Some(card.serial)
    );
    let state = client.provider.sessions.lock().unwrap()[&context.session]
        .upgrade()
        .unwrap();
    client.clear_nfc_card();
    assert!(state.lock().unwrap().stop.is_cancelled());
    assert!(client.nfc_card().is_none());
    ep.close().await;
}
