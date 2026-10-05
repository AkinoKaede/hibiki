/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Kaede Akino
 */

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
    let genesis =
        ChannelGenesis::create(&client.app.identity, hibiki_lib::random_id(), "test".into())
            .unwrap();
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

#[tokio::test]
async fn wrapping_keys_survive_background_stop_but_not_client_recreation_or_disable() {
    let (_root, client, context, card) = fixture();
    let scope = Scope::new(
        &client.app.identity.device.id(),
        &context,
        &card,
        &card.keys[0],
    );
    let mut blob = Vec::new();
    client
        .provider
        .pin_cache
        .publish(
            client.provider.pin_cache.begin(scope.clone()),
            b"123456",
            |line| {
                blob = line.rsplit(|b| *b == b' ').next().unwrap().to_vec();
                Ok(())
            },
        )
        .unwrap();
    client.stop().await;
    assert!(
        client
            .provider
            .pin_cache
            .decrypt(&client.provider.pin_cache.begin(scope.clone()), &blob)
            .is_some()
    );
    let replacement = MobileClient::new(
        client
            .app
            .paths
            .data
            .parent()
            .unwrap()
            .to_string_lossy()
            .into(),
        client.app.config.server.clone(),
        hibiki_lib::encode(client.app.identity.as_ref()).unwrap(),
        false,
    )
    .unwrap();
    assert!(
        !replacement
            .provider
            .pin_cache
            .contains(&replacement.provider.pin_cache.begin(scope.clone()))
    );
    client.set_services(true, false);
    client.set_services(true, true);
    assert!(
        client
            .provider
            .pin_cache
            .decrypt(&client.provider.pin_cache.begin(scope), &blob)
            .is_none()
    );
}
async fn next(client: &MobileClient) -> NativeEvent {
    tokio::time::timeout(Duration::from_secs(2), client.broker.next())
        .await
        .unwrap()
        .unwrap()
}

/// Model the native USB probe explicitly; public discovery must never prompt or open NFC.
async fn query_without_usb(
    client: &MobileClient,
    ep: &mut Endpoint,
    line: assuan::Line,
) -> anyhow::Result<assuan::AssuanResult> {
    let query = hibiki_core::preparation::query(ep, line);
    tokio::pin!(query);
    loop {
        tokio::select! {
            result = &mut query => return result,
            event = next(client) => match event {
                NativeEvent::CardOpen { token, transport: CardTransport::Usb, .. } => {
                    client.card_not_present(token).unwrap();
                }
                NativeEvent::Cancelled { .. } | NativeEvent::CardClose { .. } => {}
                _ => panic!("unexpected native work during public discovery"),
            }
        }
    }
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
async fn discovered_usb_prepares_without_reading_or_checking_presence_even_without_nfc() {
    for nfc in [false, true] {
        for present in [false, true] {
            let (_root, client, context, mut card) = fixture();
            client.set_nfc_available(nfc);
            client.usb_present(present);
            card.transport = CardTransport::Usb;
            let (mut preparation, mut ep) = prepare(&client, context.clone()).await;
            let state = client.provider.sessions.lock().unwrap()[&context.session]
                .upgrade()
                .unwrap();
            state.lock().unwrap().usb = Some(card.clone());
            // Metadata preparation must not even wait for a busy hardware slot.
            let _busy = client.slots.clone().acquire_owned().await.unwrap();
            assert_eq!(
                tokio::time::timeout(
                    Duration::from_millis(100),
                    preparation.poll(&mut ep, CancellationToken::new())
                )
                .await
                .unwrap()
                .unwrap(),
                Some(card.serial.clone()),
            );
            assert_eq!(
                state.lock().unwrap().prepared.as_ref().unwrap().serial,
                card.serial
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(20), client.next_event())
                    .await
                    .is_err()
            );
            ep.close().await;
        }
    }
}

#[tokio::test]
async fn undiscovered_target_is_unavailable_without_probing_or_prompting() {
    for present in [false, true] {
        let (_root, client, context, _) = fixture();
        client.usb_present(present);
        let (mut preparation, mut ep) = prepare(&client, context).await;
        let _busy = client.slots.clone().acquire_owned().await.unwrap();
        let error = tokio::time::timeout(
            Duration::from_millis(100),
            preparation.poll(&mut ep, CancellationToken::new()),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert!(error.to_string().contains("has not been discovered"));
        assert!(
            tokio::time::timeout(Duration::from_millis(20), client.next_event())
                .await
                .is_err()
        );
        ep.close().await;
    }
}

#[tokio::test]
async fn private_operation_stops_on_native_cancellation_or_fault_without_fallback() {
    for (transport, cached) in [
        (CardTransport::Nfc, false),
        (CardTransport::Nfc, true),
        (CardTransport::Usb, false),
        (CardTransport::Usb, true),
    ] {
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
            let scope = Scope::new(
                &client.app.identity.device.id(),
                &context,
                &card,
                &card.keys[0],
            );
            let mut response = "D 123456".to_owned();
            if cached {
                client
                    .provider
                    .pin_cache
                    .publish(client.provider.pin_cache.begin(scope), b"123456", |line| {
                        response = format!(
                            "D {}",
                            std::str::from_utf8(line.rsplit(|b| *b == b' ').next().unwrap())
                                .unwrap()
                        );
                        Ok(())
                    })
                    .unwrap();
            }
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
            let inquiry = ep.next().await.unwrap();
            assert!(inquiry.starts_with(if cached {
                b"INQUIRE PINCACHE_GET"
            } else {
                b"INQUIRE NEEDPIN"
            }));
            assert!(
                tokio::time::timeout(Duration::from_millis(20), client.next_event())
                    .await
                    .is_err()
            );
            ep.answer(response.as_str().into()).await.unwrap();
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
            let result = query_without_usb(&client, &mut ep, command.as_str().into())
                .await
                .unwrap();
            assert_eq!(result.success(), recorded && available);
        }
        let result = query_without_usb(&client, &mut ep, "SERIALNO --demand=ABCD".into())
            .await
            .unwrap();
        assert!(!result.success());
        while let Ok(Some(event)) =
            tokio::time::timeout(Duration::from_millis(20), client.next_event()).await
        {
            assert!(matches!(
                event,
                NativeEvent::Cancelled { .. } | NativeEvent::CardClose { .. }
            ));
        }
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

#[tokio::test]
async fn synchronous_stop_invalidates_native_requests_before_returning() {
    let (_root, client, _, _) = fixture();
    let broker = client.broker.clone();
    let waiter = tokio::spawn(async move {
        broker
            .request(
                |token| NativeEvent::CardOpen {
                    token,
                    connection: "background-reader".into(),
                    transport: CardTransport::Nfc,
                },
                &CancellationToken::new(),
                Duration::from_secs(90),
            )
            .await
    });
    let NativeEvent::CardOpen { token, .. } = next(&client).await else {
        panic!("expected a native request")
    };
    client.request_stop();
    assert!(!client.request_is_pending(token.clone()));
    assert!(client.respond(token, vec![], true).is_err());
    assert!(waiter.await.unwrap().is_err());
    client.stop().await;
}

#[tokio::test]
async fn start_joins_a_synchronously_stopped_worker_before_reconnecting() {
    let root = tempfile::tempdir().unwrap();
    let client = MobileClient::new(
        root.path().join("mobile").to_string_lossy().into(),
        "ws://127.0.0.1:1/hibiki".into(),
        create_identity("background restart".into()).unwrap(),
        false,
    )
    .unwrap();
    client.clone().start().await.unwrap();
    let old_stop = client.stop.lock().unwrap().clone();
    client.request_stop();
    assert!(old_stop.is_cancelled());
    tokio::time::timeout(Duration::from_secs(3), client.clone().start())
        .await
        .unwrap()
        .unwrap();
    assert!(!client.stop.lock().unwrap().is_cancelled());
    assert!(client.job.lock().unwrap().is_some());
    client.stop().await;
    assert!(client.job.lock().unwrap().is_none());
}
