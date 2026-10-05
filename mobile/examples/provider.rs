/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Kaede Akino
 */

//! TEST ONLY: a line-oriented bridge for the isolated APDU emulator in tests/mobile.py.
//! Never connect this diagnostic harness to real cards or production channels.
use hibiki_mobile::{
    CardReadCancellation, MobileClient, NativeEvent, PinPrompt, PromptKind, check_relay,
    create_identity,
};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};
fn emit(value: Value) {
    println!("{value}");
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.iter().any(|arg| arg == "--check-relay") {
        check_relay(
            args[2].clone(),
            create_identity("mobile-fixture".into())?,
            args.iter()
                .any(|arg| arg == "--skip-tls-certificate-validation"),
        )
        .await?;
        emit(json!({"kind":"checked"}));
        return Ok(());
    }
    let client = MobileClient::new(
        args[1].clone(),
        args[2].clone(),
        create_identity("mobile-fixture".into())?,
        args.get(3)
            .is_some_and(|arg| arg == "--skip-tls-certificate-validation"),
    )?;
    client.set_nfc_available(true); // Test harness emulates NFC hardware.
    let event_client = client.clone();
    tokio::spawn(async move {
        while let Some(event) = event_client.next_event().await {
            let value = match event {
                NativeEvent::Connection { state } => json!({"kind":"state","state":state}),
                NativeEvent::Prompt { prompt } => {
                    json!({"kind":"prompt","token":prompt.token,"request":prompt.request,"device":prompt.device_id,"prompt_kind":format!("{:?}",prompt.kind),"description":prompt.description,"insertion":matches!(prompt.kind, PromptKind::Confirm) && hibiki_mobile::card_insertion_number(prompt.description.clone()).is_some()})
                }
                NativeEvent::Cancelled { token } => json!({"kind":"cancelled","token":token}),
                NativeEvent::CardOpen {
                    token,
                    connection,
                    transport,
                } => {
                    json!({"kind":"open","token":token,"connection":connection,"transport":format!("{transport:?}")})
                }
                NativeEvent::CardTransmit {
                    token,
                    connection,
                    command,
                } => {
                    json!({"kind":"apdu","connection":connection,"token":token,"command":hex::encode(command)})
                }
                NativeEvent::CardClose { .. } => json!({"kind":"close"}),
                NativeEvent::CardChanged { card } => json!({"kind":"card","serial":card.serial}),
            };
            emit(value);
        }
    });
    client.clone().start().await?;
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Some(line) = lines.next_line().await? {
        let value: Value = serde_json::from_str(&line)?;
        if let Some(connections) = value["usb_connections"].as_array() {
            client.usb_connections(
                connections
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect(),
            );
        }
        let client = client.clone();
        tokio::spawn(async move {
            if let Err(error) = command(client, value).await {
                emit(json!({"kind":"error","message":error.to_string()}));
            }
        });
    }
    client.stop().await;
    Ok(())
}
async fn command(client: Arc<MobileClient>, v: Value) -> anyhow::Result<()> {
    let text = |name: &str| v[name].as_str().unwrap_or_default().to_string();
    match text("action").as_str() {
        "nfc_capability" => {
            client.set_nfc_available(v["available"].as_bool().unwrap_or(false));
            emit(json!({"kind":"nfc-capability"}));
        }

        "ping" => {
            let report = client
                .ping_device(
                    text("channel"),
                    text("device"),
                    4,
                    hibiki_mobile::PingCancellation::new(),
                )
                .await?;
            emit(
                json!({"kind":"ping","setup_micros":report.setup_micros,"round_trips_micros":report.round_trips_micros}),
            );
        }
        "policy" => {
            emit(json!({"kind":"policy","allow_creation":client.allows_channel_creation().await?}));
        }
        "reject" => {
            client.reject_join(text("channel"), text("request")).await?;
            emit(json!({"kind":"rejected"}));
        }
        "withdraw" => {
            client
                .withdraw_join(text("channel"), text("request"))
                .await?;
            emit(json!({"kind":"withdrawn"}));
        }
        "pairing_status" => {
            let state = client
                .pairing_status(text("channel"), text("request"))
                .await?;
            emit(json!({"kind":"pairing_status","state":format!("{state:?}")}));
        }
        "create" => {
            let result = client.create_channel(text("name")).await?;
            emit(
                json!({"kind":"created","channel":result.channel,"invite":result.invite,"expires_at":result.expires_at}),
            );
        }
        "pending" => {
            let result = client.pending(text("channel")).await?;
            emit(
                json!({"kind":"pending","requests":result.iter().map(|r|json!({"id":r.id,"device":r.device.id,"words":r.device.words})).collect::<Vec<_>>()}),
            );
        }
        "approve" => {
            client.approve(text("channel"), text("request")).await?;
            emit(json!({"kind":"approved"}));
        }
        "revoke" => {
            client.revoke(text("channel"), text("device")).await?;
            emit(json!({"kind":"revoked"}));
        }
        "leave" => {
            client.leave(text("channel")).await?;
            emit(json!({"kind":"left"}));
        }
        "invite" => {
            let value = client.invitation(text("channel")).await?;
            emit(json!({"kind":"invitation","invite":value.invite,"expires_at":value.expires_at}));
        }
        "approve_verification" => {
            let cancellation = hibiki_mobile::PairingCancellation::new();
            if v["cancel"].as_bool().unwrap_or(false) {
                cancellation.cancel();
            }
            client
                .approve_verification(text("channel"), text("request"), text("code"), cancellation)
                .await?;
            emit(json!({"kind":"approved"}));
        }
        "join" => {
            let joined = client.join(text("invite")).await?;
            emit(
                json!({"kind":"joined","request":joined.request,"channel":joined.channel,"verification":joined.verification}),
            );
        }
        "record_nfc" => {
            let card = client
                .record_nfc_card(None, CardReadCancellation::new())
                .await?;
            client.usb_present(v["present"].as_bool().unwrap_or(false));
            client.set_services(true, true);
            emit(json!({"kind":"recorded","serial":card.serial,"keys":card.keys.len()}));
        }
        "clear_nfc" => {
            client.clear_nfc_card();
            emit(json!({"kind":"nfc-cleared"}));
        }
        "continue_insertion" => {
            let prompt = &v["prompt"];
            let p = PinPrompt {
                token: prompt["token"].as_str().unwrap_or_default().into(),
                session: String::new(),
                request: 0,
                channel: String::new(),
                device_name: String::new(),
                device_id: String::new(),
                kind: PromptKind::Confirm,
                title: String::new(),
                description: prompt["description"].as_str().unwrap_or_default().into(),
                label: String::new(),
                error: String::new(),
                repeat: String::new(),
                repeat_error: String::new(),
                ok: String::new(),
                cancel: String::new(),
                not_ok: String::new(),
                timeout_seconds: 120,
            };
            client
                .continue_card_insertion(p, CardReadCancellation::new())
                .await?;
            emit(json!({"kind":"insertion-continued"}));
        }
        "reply" => {
            let _ = client.respond(
                text("token"),
                hex::decode(text("data"))?,
                v["accepted"].as_bool().unwrap_or(true),
            );
        }
        "card_not_present" => {
            let _ = client.card_not_present(text("token"));
        }
        "cancel_request" => {
            let _ = client.cancel_request(text("token"));
        }
        "services" => {
            client.set_services(
                v["pin"].as_bool().unwrap_or(false),
                v["card"].as_bool().unwrap_or(false),
            );
            emit(json!({"kind":"services"}));
        }
        "usb_presence" => {
            let present = v["present"].as_bool().unwrap_or(false);
            client.usb_present(present);
            emit(json!({"kind":"usb-presence","present":present}));
        }
        "stop" => {
            client.stop().await;
            emit(json!({"kind":"stopped"}));
        }
        "start" => {
            client.start().await?;
            emit(json!({"kind":"started"}));
        }
        _ => anyhow::bail!("unknown fixture command"),
    }
    Ok(())
}
