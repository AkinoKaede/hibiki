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
    let before = encode(&core.nfc_card()).unwrap();
    core.set_nfc_available(false);
    assert!(
        core.inspect_card(CardTransport::Nfc, CardReadCancellation::new())
            .await
            .is_err()
    );
    assert!(
        core.record_nfc_card(CardReadCancellation::new())
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

#[test]
fn records_are_not_loaded_and_legacy_files_are_removed_without_decoding() {
    let root = tempfile::tempdir().unwrap();
    let core = client(root.path());
    seed(&core);
    for name in ["cards.bin", "nfc-cards.bin"] {
        std::fs::write(
            core.app.paths.data.join(name),
            b"obsolete or corrupted registry",
        )
        .unwrap();
    }
    let reopened = client(root.path());
    assert!(reopened.nfc_card().is_none());
    for name in ["cards.bin", "nfc-cards.bin"] {
        assert!(!core.app.paths.data.join(name).exists());
    }
    assert_eq!(core.nfc_card().unwrap().serial, "previous");
    core.clear_nfc_card();
    assert!(core.nfc_card().is_none());
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
    let task =
        tokio::spawn(async move { reader.record_nfc_card(CardReadCancellation::new()).await });
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
        core.record_nfc_card(CardReadCancellation::new())
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
