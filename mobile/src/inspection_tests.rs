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
    let mut registry = registry::Registry::default();
    for serial in ["first", "selected"] {
        registry.upsert(
            CardInfo {
                serial: serial.into(),
                transport: CardTransport::Nfc,
                keys: vec![],
            },
            serial.into(),
            true,
            true,
        );
    }
    client.save_registry(registry).unwrap();
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
    let before = encode(&core.registered_cards()).unwrap();
    core.set_nfc_available(false);
    assert!(
        core.inspect_card(CardTransport::Nfc, CardReadCancellation::new())
            .await
            .is_err()
    );
    assert!(
        core.register_card(CardTransport::Nfc, "new".into(), false, true)
            .await
            .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(20), core.next_event())
            .await
            .is_err()
    );
    assert_eq!(encode(&core.registered_cards()).unwrap(), before);
}

#[tokio::test]
async fn edits_preserve_all_public_data_and_persist_connection_changes() {
    let root = tempfile::tempdir().unwrap();
    let core = client(root.path());
    seed(&core);
    let original = encode(&core.registered_cards()[0].card).unwrap();
    core.update_card("first".into(), "  Renamed  ".into(), false, true)
        .await
        .unwrap();
    assert_eq!(core.registered_cards()[1].card.serial, "selected");
    assert_eq!(encode(&core.registered_cards()[0].card).unwrap(), original);
    assert_eq!(core.registered_cards()[0].name, "Renamed");
    assert!(core.registered_cards()[1].usb_enabled);
    core.update_card("selected".into(), "USB only".into(), true, false)
        .await
        .unwrap();
    assert!(!core.registered_cards()[1].nfc_enabled);
    core.update_card("selected".into(), "NFC only".into(), false, true)
        .await
        .unwrap();
    assert!(!core.registered_cards()[1].usb_enabled);
    assert!(core.registered_cards()[1].nfc_enabled);
    let before = read_private(&core.registry_path()).unwrap();
    for (serial, name, usb, nfc) in [
        ("selected", " \n ", true, true),
        ("selected", "Invalid", false, false),
        ("unknown", "Missing", true, true),
    ] {
        assert!(
            core.update_card(serial.into(), name.into(), usb, nfc)
                .await
                .is_err()
        );
        assert_eq!(read_private(&core.registry_path()).unwrap(), before);
    }
    drop(core);
    let reopened = client(root.path());
    assert_eq!(reopened.registered_cards()[0].name, "Renamed");
    assert_eq!(reopened.registered_cards()[1].card.serial, "selected");
    assert!(!reopened.registered_cards()[1].usb_enabled);
    assert_eq!(reopened.registered_cards()[1].name, "NFC only");
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
async fn usb_registration_without_nfc_preserves_existing_hidden_capability() {
    for existing in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let core = client(root.path());
        core.set_nfc_available(false);
        if existing {
            let mut registry = registry::Registry::default();
            registry.upsert(
                CardInfo {
                    serial: "D2760001240103040005000012340000".into(),
                    transport: CardTransport::Nfc,
                    keys: vec![],
                },
                "Existing".into(),
                true,
                true,
            );
            core.save_registry(registry).unwrap();
        }
        let reader = core.clone();
        let task = tokio::spawn(async move {
            reader
                .register_card(CardTransport::Usb, "Renamed".into(), true, false)
                .await
        });
        loop {
            match next(&core).await {
                NativeEvent::CardOpen { token, .. } => {
                    core.respond(token, vec![], true).unwrap();
                }
                NativeEvent::CardTransmit { token, command, .. } => {
                    let response = match (command[1], command[3]) {
                        (0xA4, _) => vec![0x90, 0],
                        (0xCA, 0x6E) => application_data(),
                        (0xCA, 0x65) => vec![0x6A, 0x88], // Optional cardholder name.
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
        let cards = core.registered_cards();
        assert_eq!(cards.len(), 1);
        assert_eq!(cards[0].nfc_enabled, existing);
        assert!(cards[0].usb_enabled);
    }
}

#[tokio::test]
async fn inspection_reads_both_interfaces_without_changing_registry_or_requesting_pin() {
    let root = tempfile::tempdir().unwrap();
    let core = client(root.path());
    seed(&core);
    let before = read_private(&core.registry_path()).unwrap();
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
        assert_eq!(read_private(&core.registry_path()).unwrap(), before);
        assert_eq!(core.registered_cards()[1].card.serial, "selected");
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
        core.update_card("selected".into(), "Busy".into(), true, false)
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
    core.update_card("selected".into(), "After cancellation".into(), true, false)
        .await
        .unwrap();
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
