//! TEST ONLY: a line-oriented bridge for the isolated APDU emulator in tests/mobile.py.
//! Never connect this diagnostic harness to real cards or production channels.
use hibiki_mobile::{CardTransport, MobileClient, NativeEvent, check_relay, create_identity};
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
    let event_client = client.clone();
    tokio::spawn(async move {
        while let Some(event) = event_client.next_event().await {
            let value = match event {
                NativeEvent::Connection { state } => json!({"kind":"state","state":state}),
                NativeEvent::Prompt { prompt } => {
                    json!({"kind":"prompt","token":prompt.token,"request":prompt.request,"device":prompt.device_id,"prompt_kind":format!("{:?}",prompt.kind)})
                }
                NativeEvent::Cancelled { token } => json!({"kind":"cancelled","token":token}),
                NativeEvent::CardOpen {
                    token,
                    connection,
                    transport,
                } => {
                    json!({"kind":"open","token":token,"connection":connection,"transport":format!("{transport:?}")})
                }
                NativeEvent::CardTransmit { token, command, .. } => {
                    json!({"kind":"apdu","token":token,"command":hex::encode(command)})
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
        "create" => {
            let result = client.create_channel(text("name")).await?;
            emit(
                json!({"kind":"created","channel":result.channel,"invite":result.invite,"psk":result.psk}),
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
        "rotate" => {
            let psk = client.rotate_psk(text("channel")).await?;
            emit(json!({"kind":"rotated","psk":psk}));
        }
        "revoke" => {
            client.revoke(text("channel"), text("device")).await?;
            emit(json!({"kind":"revoked"}));
        }
        "leave" => {
            client.leave(text("channel")).await?;
            emit(json!({"kind":"left"}));
        }
        "join" => {
            let joined = client.join(text("invite"), text("psk")).await?;
            emit(json!({"kind":"joined","request":joined.request,"channel":joined.channel}));
        }
        "register" => {
            let transport = if v["transport"] == "usb" {
                CardTransport::Usb
            } else {
                CardTransport::Nfc
            };
            let card = client
                .register_card(
                    transport,
                    "Test key".into(),
                    v["usb_supported"].as_bool().unwrap_or(true),
                    v["nfc_supported"].as_bool().unwrap_or(true),
                )
                .await?;
            client.usb_present(v["present"].as_bool().unwrap_or(false));
            client.set_services(true, true);
            emit(json!({"kind":"registered","serial":card.serial,"keys":card.keys.len()}));
        }
        "reply" => {
            let _ = client.respond(
                text("token"),
                hex::decode(text("data"))?,
                v["accepted"].as_bool().unwrap_or(true),
            );
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
