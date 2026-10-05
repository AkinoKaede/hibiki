/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Kaede Akino
 */

use super::*;

fn client(root: &std::path::Path) -> Arc<MobileClient> {
    let core = MobileClient::new(
        root.join("mobile").to_string_lossy().into(),
        "wss://example.com/hibiki".into(),
        create_identity("inspection test".into()).unwrap(),
        false,
    )
    .unwrap();
    core.set_nfc_available(true);
    core
}

fn seed(client: &MobileClient) {
    *client.provider.nfc_card.lock().unwrap() = Some(CardInfo {
        serial: "previous".into(),
        transport: CardTransport::Nfc,
        keys: vec![],
    });
}

fn cached_scope(core: &MobileClient, serial: &str) -> crate::pin_cache::Scope {
    let context = hibiki_core::provider::ProviderContext {
        local: None,
        channel: "channel".into(),
        peer: "peer".into(),
        session: "session".into(),
    };
    let key = CardKey {
        slot: 1,
        algorithm: "rsa2048".into(),
        fingerprint: "A".repeat(40),
        keygrip: "B".repeat(40),
        public_key: vec![],
        created_at: 0,
    };
    let info = CardInfo {
        serial: serial.into(),
        transport: CardTransport::Nfc,
        keys: vec![],
    };
    let scope = crate::pin_cache::Scope::new("provider", &context, &info, &key);
    let cache = &core.provider.pin_cache;
    cache
        .publish(cache.begin(scope.clone()), b"123456", |_| Ok(()))
        .unwrap();
    scope
}

async fn next(client: &MobileClient) -> NativeEvent {
    tokio::time::timeout(Duration::from_secs(3), client.next_event())
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn unavailable_nfc_cannot_open_native_reader_or_register_a_card() {
    let root = tempfile::tempdir().unwrap();
    let core = client(root.path());
    seed(&core);
    core.set_nfc_available(false);
    let before = encode(&core.nfc_card()).unwrap();
    assert!(
        core.inspect_card(CardTransport::Nfc, CardReadCancellation::new())
            .await
            .is_err()
    );
    assert!(
        core.record_nfc_card(None, CardReadCancellation::new())
            .await
            .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(20), core.next_event())
            .await
            .is_err()
    );
    assert_eq!(encode(&core.nfc_card()).unwrap(), before);
}

// An empty OpenPGP card is enough to verify the production public-read path.
fn application_data() -> Vec<u8> {
    let mut data =
        hex::decode("4F10D27600012401030400050000123400005F520800730000C0009000").unwrap();
    let mut discretionary = hex::decode("C00A00000000080008000000C407017F7F7F030303C53C").unwrap();
    discretionary.extend([0; 60]);
    discretionary.extend([0xCD, 12]);
    discretionary.extend([0; 12]);
    data.extend([0x73, discretionary.len() as u8]);
    data.extend(discretionary);
    data.extend([0x90, 0x00]);
    data
}

#[tokio::test]
async fn recording_reads_public_data_and_is_not_persisted() {
    let root = tempfile::tempdir().unwrap();
    let core = client(root.path());
    let reader = core.clone();
    let task = tokio::spawn(async move {
        reader
            .record_nfc_card(None, CardReadCancellation::new())
            .await
    });
    loop {
        match next(&core).await {
            NativeEvent::CardOpen {
                token, transport, ..
            } => {
                assert_eq!(transport, CardTransport::Nfc);
                core.respond(token, vec![], true).unwrap();
            }
            NativeEvent::CardTransmit { token, command, .. } => {
                let response = match (command[1], command[3]) {
                    (0xA4, _) => vec![0x90, 0],
                    (0xCA, 0x6E) => application_data(),
                    (0xCA, 0x65) => vec![0x6A, 0x88],
                    _ => panic!("registration must only read public data"),
                };
                core.respond(token, response, true).unwrap();
            }
            NativeEvent::CardClose { .. } => break,
            NativeEvent::Cancelled { .. } => {}
            _ => panic!("unexpected registration event"),
        }
    }
    task.await.unwrap().unwrap();
    let card = core.nfc_card().unwrap();
    assert_eq!(card.transport, CardTransport::Nfc);
    assert_eq!(card.serial, "D2760001240103040005000012340000");
    assert!(client(root.path()).nfc_card().is_none());
    assert!(!core.app.paths.data.join("nfc-cards.bin").exists());
}

#[tokio::test]
async fn inspection_reads_both_interfaces_without_changing_registry_or_requesting_pin() {
    let root = tempfile::tempdir().unwrap();
    let core = client(root.path());
    seed(&core);
    let before = encode(&core.nfc_card()).unwrap();
    for transport in [CardTransport::Usb, CardTransport::Nfc] {
        let reader = core.clone();
        let mode = transport.clone();
        let read =
            tokio::spawn(
                async move { reader.inspect_card(mode, CardReadCancellation::new()).await },
            );
        loop {
            match next(&core).await {
                NativeEvent::CardOpen {
                    token,
                    transport: actual,
                    ..
                } => {
                    assert_eq!(actual, transport);
                    core.respond(token, vec![], true).unwrap();
                }
                NativeEvent::CardTransmit { token, command, .. } => {
                    let response = match command[1] {
                        0xA4 => vec![0x90, 0],
                        0xCA => {
                            assert_eq!(&command[2..4], &[0, 0x6E]);
                            application_data()
                        }
                        _ => panic!("inspection must only select and read public data"),
                    };
                    core.respond(token, response, true).unwrap();
                }
                NativeEvent::CardClose { .. } => break,
                NativeEvent::Cancelled { .. } => {}
                _ => panic!("inspection must not prompt for a PIN or change registrations"),
            }
        }
        let info = read.await.unwrap().unwrap();
        assert_eq!(info.serial, "D2760001240103040005000012340000");
        assert_eq!(info.transport, transport);
        assert!(info.keys.is_empty());
        assert_eq!(encode(&core.nfc_card()).unwrap(), before);
        assert_eq!(core.nfc_card().unwrap().serial, "previous");
        assert_eq!(core.slots.available_permits(), 1);
    }
}

#[tokio::test]
async fn inspection_cancellation_releases_hardware_and_rejects_late_responses() {
    let root = tempfile::tempdir().unwrap();
    let core = client(root.path());
    seed(&core);
    let cancellation = CardReadCancellation::new();
    let read_cancel = cancellation.clone();
    let reader = core.clone();
    let read =
        tokio::spawn(async move { reader.inspect_card(CardTransport::Nfc, read_cancel).await });
    let NativeEvent::CardOpen {
        token, connection, ..
    } = next(&core).await
    else {
        panic!()
    };
    assert!(
        core.inspect_card(CardTransport::Usb, CardReadCancellation::new())
            .await
            .is_err()
    );
    assert!(
        core.record_nfc_card(None, CardReadCancellation::new())
            .await
            .is_err()
    );
    cancellation.cancel();
    assert!(matches!(read.await.unwrap(), Err(MobileError::Cancelled)));
    assert_eq!(core.slots.available_permits(), 1);
    assert!(!core.request_is_pending(token.clone()));
    assert!(core.respond(token, vec![], true).is_err());
    loop {
        if let NativeEvent::CardClose { connection: closed } = next(&core).await {
            assert_eq!(closed, connection);
            break;
        }
    }
    // A pre-canceled handle cannot open a reader, even before the async call starts.
    assert!(matches!(
        core.inspect_card(CardTransport::Usb, cancellation).await,
        Err(MobileError::Cancelled)
    ));
    assert_eq!(core.nfc_card().unwrap().serial, "previous");
}

#[tokio::test]
async fn native_read_errors_and_user_cancellation_are_distinct() {
    for canceled in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let core = client(root.path());
        let reader = core.clone();
        let read = tokio::spawn(async move {
            reader
                .inspect_card(CardTransport::Nfc, CardReadCancellation::new())
                .await
        });
        let NativeEvent::CardOpen { token, .. } = next(&core).await else {
            panic!()
        };
        core.fail_native_request(token, "Reader unavailable".into(), canceled)
            .unwrap();
        let result = read.await.unwrap();
        if canceled {
            assert!(matches!(result, Err(MobileError::Cancelled)));
        } else {
            assert!(
                matches!(result, Err(MobileError::Failed { message }) if message == "Reader unavailable")
            );
        }
        assert_eq!(core.slots.available_permits(), 1);
    }
}

#[tokio::test]
async fn cancellation_during_transmit_and_background_stop_release_the_reader() {
    for background in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let core = client(root.path());
        let reader = core.clone();
        let read = tokio::spawn(async move {
            reader
                .inspect_card(CardTransport::Nfc, CardReadCancellation::new())
                .await
        });
        let NativeEvent::CardOpen { token, .. } = next(&core).await else {
            panic!()
        };
        core.respond(token, vec![], true).unwrap();
        let token = loop {
            match next(&core).await {
                NativeEvent::CardTransmit { token, .. } => break token,
                NativeEvent::Cancelled { .. } => {}
                _ => panic!(),
            }
        };
        if background {
            core.stop().await;
        } else {
            core.fail_native_request(token.clone(), "NFC canceled".into(), true)
                .unwrap();
        }
        assert!(matches!(read.await.unwrap(), Err(MobileError::Cancelled)));
        assert_eq!(core.slots.available_permits(), 1);
        assert!(!core.request_is_pending(token));
    }
}

fn insertion_prompt(kind: PromptKind, description: &str) -> PinPrompt {
    PinPrompt {
        token: String::new(),
        session: "insertion-test".into(),
        request: 1,
        channel: String::new(),
        device_name: String::new(),
        device_id: String::new(),
        kind,
        title: String::new(),
        description: description.into(),
        label: String::new(),
        error: String::new(),
        repeat: String::new(),
        repeat_error: String::new(),
        ok: String::new(),
        cancel: String::new(),
        not_ok: String::new(),
        timeout_seconds: 30,
    }
}

async fn pending_insertion(
    core: &MobileClient,
) -> (
    PinPrompt,
    tokio::task::JoinHandle<anyhow::Result<zeroize::Zeroizing<Vec<u8>>>>,
) {
    let broker = core.broker.clone();
    let reply = tokio::spawn(async move {
        broker
            .request(
                |token| {
                    let mut prompt = insertion_prompt(
                        PromptKind::Confirm,
                        "Please insert the card with serial number:\n\n  0005 00001234\n  ",
                    );
                    prompt.token = token;
                    NativeEvent::Prompt { prompt }
                },
                &CancellationToken::new(),
                Duration::from_secs(30),
            )
            .await
    });
    let NativeEvent::Prompt { prompt } = next(core).await else {
        panic!()
    };
    (prompt, reply)
}

async fn finish_public_read(core: &MobileClient, transport: CardTransport) {
    loop {
        match next(core).await {
            NativeEvent::CardOpen {
                token,
                transport: actual,
                ..
            } => {
                assert_eq!(actual, transport);
                core.respond(token, vec![], true).unwrap();
            }
            NativeEvent::CardTransmit { token, command, .. } => {
                let response = match command[1] {
                    0xA4 => vec![0x90, 0],
                    0xCA => application_data(),
                    _ => panic!("public read must not verify a PIN"),
                };
                core.respond(token, response, true).unwrap();
            }
            NativeEvent::CardClose { .. } => return,
            NativeEvent::Cancelled { .. } | NativeEvent::CardChanged { .. } => {}
            _ => panic!("unexpected prompt while reading"),
        }
    }
}

#[tokio::test]
async fn insertion_acknowledges_before_scanning_and_uses_usb_first() {
    for usb in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let core = client(root.path());
        core.usb_present(usb);
        let (prompt, reply) = pending_insertion(&core).await;
        let token = prompt.token.clone();
        let reader = core.clone();
        let task = tokio::spawn(async move {
            reader
                .continue_card_insertion(prompt, CardReadCancellation::new())
                .await
        });
        // The original CONFIRM is already answered while no native reader has replied.
        tokio::time::timeout(Duration::from_secs(2), reply)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(!core.request_is_pending(token));
        finish_public_read(
            &core,
            if usb {
                CardTransport::Usb
            } else {
                CardTransport::Nfc
            },
        )
        .await;
        task.await.unwrap().unwrap();
        assert_eq!(core.nfc_card().is_some(), !usb);
        assert_eq!(core.slots.available_permits(), 1);
    }
}

#[tokio::test]
async fn only_insertion_confirmations_can_start_the_insertion_reader() {
    let root = tempfile::tempdir().unwrap();
    let core = client(root.path());
    let description = "Please insert the card with serial number: 0005 00001234";
    for prompt in [
        insertion_prompt(PromptKind::Message, description),
        insertion_prompt(PromptKind::Pin, description),
        insertion_prompt(PromptKind::Confirm, "Allow access to this key?"),
    ] {
        assert!(
            core.continue_card_insertion(prompt, CardReadCancellation::new())
                .await
                .is_err()
        );
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(20), core.next_event())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn rerecord_replaces_only_on_success_and_can_be_canceled_or_cleared() {
    for outcome in [
        "success",
        "same-card",
        "wrong-card",
        "cancel",
        "clear",
        "background",
        "error",
    ] {
        let root = tempfile::tempdir().unwrap();
        let core = client(root.path());
        seed(&core);
        if outcome == "same-card" {
            core.provider
                .nfc_card
                .lock()
                .unwrap()
                .as_mut()
                .unwrap()
                .serial = "D2760001240103040005000012340000".into();
        }
        let previous = core.nfc_card().unwrap().serial;
        let scope = cached_scope(&core, &previous);
        let other = cached_scope(&core, "unrelated-card");
        let stale = core.provider.pin_cache.begin(scope.clone());
        let cancellation = CardReadCancellation::new();
        let handle = cancellation.clone();
        let reader = core.clone();
        let expected = (outcome == "wrong-card").then(|| "0005 99999999".into());
        let task = tokio::spawn(async move { reader.record_nfc_card(expected, handle).await });
        if matches!(outcome, "success" | "same-card" | "wrong-card") {
            finish_public_read(&core, CardTransport::Nfc).await;
        } else {
            let NativeEvent::CardOpen { token, .. } = next(&core).await else {
                panic!()
            };
            match outcome {
                "cancel" => cancellation.cancel(),
                "clear" => core.clear_nfc_card(),
                "background" => core.stop().await,
                _ => core
                    .fail_native_request(token, "reader error".into(), false)
                    .unwrap(),
            }
        }
        assert_eq!(
            task.await.unwrap().is_ok(),
            matches!(outcome, "success" | "same-card")
        );
        let cache = &core.provider.pin_cache;
        assert_eq!(
            cache.contains(&cache.begin(scope)),
            !matches!(outcome, "success" | "clear")
        );
        assert!(cache.contains(&cache.begin(other)));
        if matches!(outcome, "success" | "clear") {
            cache
                .publish(stale, b"123456", |_| panic!("stale NFC PUT"))
                .unwrap();
        }
        assert_eq!(
            core.nfc_card().map(|c| c.serial),
            match outcome {
                "clear" => None,
                "success" | "same-card" => Some("D2760001240103040005000012340000".into()),
                _ => Some("previous".into()),
            }
        );
        assert_eq!(core.slots.available_permits(), 1);
    }
}

#[tokio::test]
async fn insertion_usb_errors_do_not_fall_back_but_absence_does() {
    for absent in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let core = client(root.path());
        seed(&core);
        core.usb_present(true);
        let (prompt, reply) = pending_insertion(&core).await;
        let reader = core.clone();
        let task = tokio::spawn(async move {
            reader
                .continue_card_insertion(prompt, CardReadCancellation::new())
                .await
        });
        reply.await.unwrap().unwrap();
        let token = loop {
            if let NativeEvent::CardOpen {
                token, transport, ..
            } = next(&core).await
            {
                assert_eq!(transport, CardTransport::Usb);
                break token;
            }
        };
        if absent {
            core.card_not_present(token).unwrap();
            // Consume the closed USB probe before servicing NFC.
            loop {
                if matches!(next(&core).await, NativeEvent::CardClose { .. }) {
                    break;
                }
            }
            finish_public_read(&core, CardTransport::Nfc).await;
            task.await.unwrap().unwrap();
        } else {
            core.fail_native_request(token, "USB failed".into(), false)
                .unwrap();
            assert!(task.await.unwrap().is_err());
            assert_eq!(core.nfc_card().unwrap().serial, "previous");
            while let Ok(Some(event)) =
                tokio::time::timeout(Duration::from_millis(20), core.next_event()).await
            {
                assert!(!matches!(event, NativeEvent::CardOpen { .. }));
            }
        }
    }
}

#[tokio::test]
async fn new_pinentry_requests_remain_pending_during_an_independent_nfc_read() {
    for canceled in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let core = client(root.path());
        let (prompt, first_reply) = pending_insertion(&core).await;
        let old_token = prompt.token.clone();
        let cancellation = CardReadCancellation::new();
        let handle = cancellation.clone();
        let reader = core.clone();
        let read =
            tokio::spawn(async move { reader.continue_card_insertion(prompt, handle).await });
        first_reply.await.unwrap().unwrap();
        let reader_token = loop {
            if let NativeEvent::CardOpen {
                token, transport, ..
            } = next(&core).await
            {
                assert_eq!(transport, CardTransport::Nfc);
                break token;
            }
        };
        let broker = core.broker.clone();
        let second_reply = tokio::spawn(async move {
            broker
                .request(
                    |token| {
                        let mut prompt = insertion_prompt(PromptKind::Pin, "Please enter the PIN");
                        prompt.token = token;
                        NativeEvent::Prompt { prompt }
                    },
                    &CancellationToken::new(),
                    Duration::from_secs(30),
                )
                .await
        });
        let second_token = loop {
            if let NativeEvent::Prompt { prompt } = next(&core).await {
                break prompt.token;
            }
        };
        assert!(!core.request_is_pending(old_token.clone()));
        assert!(core.request_is_pending(reader_token.clone()));
        assert!(core.request_is_pending(second_token.clone()));
        assert!(!second_reply.is_finished());
        assert!(core.cancel_request(old_token).is_err());
        if canceled {
            cancellation.cancel();
        } else {
            core.respond(reader_token, vec![], true).unwrap();
            finish_public_read(&core, CardTransport::Nfc).await;
        }
        assert_eq!(read.await.unwrap().is_ok(), !canceled);
        assert!(core.request_is_pending(second_token.clone()));
        assert!(
            !second_reply.is_finished(),
            "scanner must not answer queued prompts"
        );
        core.respond(second_token, b"123456".to_vec(), true)
            .unwrap();
        assert_eq!(&*second_reply.await.unwrap().unwrap(), b"123456");
    }
}

#[tokio::test]
async fn a_wrong_usb_card_does_not_open_nfc_or_replace_the_record() {
    let root = tempfile::tempdir().unwrap();
    let core = client(root.path());
    seed(&core);
    core.usb_present(true);
    let (mut prompt, reply) = pending_insertion(&core).await;
    prompt.description = "Please insert the card with serial number: 0005 99999999".into();
    let reader = core.clone();
    let task = tokio::spawn(async move {
        reader
            .continue_card_insertion(prompt, CardReadCancellation::new())
            .await
    });
    reply.await.unwrap().unwrap();
    finish_public_read(&core, CardTransport::Usb).await;
    assert!(task.await.unwrap().is_err());
    assert_eq!(core.nfc_card().unwrap().serial, "previous");
    while let Ok(Some(event)) =
        tokio::time::timeout(Duration::from_millis(20), core.next_event()).await
    {
        assert!(!matches!(event, NativeEvent::CardOpen { .. }));
    }
}

#[tokio::test]
async fn insertion_on_a_device_without_nfc_is_an_ordinary_confirmation() {
    let root = tempfile::tempdir().unwrap();
    let core = client(root.path());
    core.set_nfc_available(false);
    core.usb_present(true);
    let (prompt, reply) = pending_insertion(&core).await;
    core.continue_card_insertion(prompt, CardReadCancellation::new())
        .await
        .unwrap();
    reply.await.unwrap().unwrap();
    while let Ok(Some(event)) =
        tokio::time::timeout(Duration::from_millis(20), core.next_event()).await
    {
        assert!(
            matches!(event, NativeEvent::Cancelled { .. }),
            "ordinary confirmation must not open a reader"
        );
    }
}

#[tokio::test]
async fn usb_identification_tracks_native_insertions_and_rejects_late_reads() {
    for removed_during_read in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let core = client(root.path());
        core.usb_connections(vec!["insertion".into()]);
        let scope = cached_scope(&core, "D2760001240103040005000012340000");
        let other = cached_scope(&core, "other-card");
        let reader = core.clone();
        let read = tokio::spawn(async move {
            reader
                .inspect_card(CardTransport::Usb, CardReadCancellation::new())
                .await
        });
        loop {
            match next(&core).await {
                NativeEvent::CardOpen { token, .. } => {
                    core.respond(token, b"insertion".to_vec(), true).unwrap();
                }
                NativeEvent::CardTransmit { token, command, .. } => {
                    let response = match command[1] {
                        0xA4 => vec![0x90, 0],
                        0xCA => {
                            if removed_during_read {
                                core.usb_connections(vec![]);
                            }
                            application_data()
                        }
                        _ => panic!("only public APDUs expected"),
                    };
                    core.respond(token, response, true).unwrap();
                }
                NativeEvent::CardClose { .. } => break,
                NativeEvent::Cancelled { .. } => {}
                _ => panic!("unexpected event"),
            }
        }
        assert_eq!(read.await.unwrap().is_err(), removed_during_read);
        if !removed_during_read {
            core.usb_connections(vec!["replacement".into()]);
        }
        assert!(
            !core
                .provider
                .pin_cache
                .contains(&core.provider.pin_cache.begin(scope))
        );
        assert!(
            core.provider
                .pin_cache
                .contains(&core.provider.pin_cache.begin(other))
        );
        assert!(
            core.provider
                .pin_cache
                .observe_usb("insertion", "late")
                .is_err()
        );
    }
}

#[tokio::test]
async fn first_serialno_after_usb_reinsertion_waits_for_live_card_despite_stale_presence() {
    use hibiki_core::provider::{Provider, ProviderContext};
    use hibiki_lib::protocol::ServiceKind;
    let serial = "D2760001240103040005000012340000";
    for command in [
        "SERIALNO".to_owned(),
        "SERIALNO --all".into(),
        format!("SERIALNO --demand={serial}"),
    ] {
        let root = tempfile::tempdir().unwrap();
        let core = client(root.path());
        core.usb_connections(vec!["old-insertion".into()]);
        core.usb_connections(vec![]);
        // The physical card has been reinserted, but its presence event has not arrived.
        let mut ep = core
            .provider
            .open(
                core.app.clone(),
                ServiceKind::Scdaemon,
                core.slots.clone(),
                CancellationToken::new(),
                ProviderContext {
                    local: None,
                    channel: "channel".into(),
                    peer: "peer".into(),
                    session: "reinsert".into(),
                },
            )
            .await
            .unwrap();
        ep.command(command.as_str().into()).await.unwrap();
        let token = match next(&core).await {
            NativeEvent::CardOpen {
                token,
                transport: CardTransport::Usb,
                ..
            } => token,
            _ => panic!("SERIALNO must probe USB without an insertion prompt"),
        };
        assert!(
            ep.rx.try_recv().is_err(),
            "SERIALNO replied before the live probe completed"
        );
        core.usb_connections(vec!["new-insertion".into()]);
        core.respond(token, b"new-insertion".to_vec(), true)
            .unwrap();
        finish_public_read(&core, CardTransport::Usb).await;
        assert_eq!(
            &*ep.next().await.unwrap(),
            format!("S SERIALNO {serial}").as_bytes()
        );
        assert_eq!(&*ep.next().await.unwrap(), b"OK");
        ep.close().await;
    }
}
