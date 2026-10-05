# Hibiki

Use an OpenPGP Card on another device and enter its PIN on any participating
device. Hibiki forwards **scdaemon and Pinentry over Assuan stdio**, while your
native `gpg`, `gpg-agent`, and Git signing workflow stay on the requesting machine.

For example, laptop A can sign a commit using a card attached to desktop B, with
the PIN entered on device C. Multiple devices can offer input at once; the first
successful response wins and the other prompts close.

## Features

- **Remote card access:** discover an OpenPGP Card, learn its public keys, sign,
  and decrypt through your existing GPG workflow.
- **Terminal management:** `hibiki tui` manages channels, devices, requests, invitations and local settings. CLI queries also support versioned JSON.
- **Peer diagnostics:** encrypted device-to-device Ping separates connection setup from established round-trip latency.
- **Remote password entry:** use another device's native Pinentry or the iOS app
  for card PINs and software-key passphrases.
- **Independent device roles:** provide card access, password entry, both, or
  neither. Both services are disabled by default.
- **Encrypted peer sessions:** devices authenticate with Ed25519 identities and
  exchange Assuan traffic over Noise sessions through a WebSocket relay.
- **Native iOS support:** the SwiftUI app supports iOS 18+ with wired and NFC
  OpenPGP card access, password entry, and channel management while open.

Card private keys stay on the card; software private keys stay on the requesting
device. The relay sees routing metadata but cannot read Assuan traffic. PINs pass
through the input device and requester, and card PINs also reach the selected card
provider. See the [trust model](ARCHITECTURE.md#trust-and-storage).

## Documentation

| Guide | What it covers |
| --- | --- |
| [Usage](USAGE.md) | Installation, relay deployment, pairing, provider settings, GPG/Git signing, diagnostics, and administration |
| [Upgrade notes](UPGRADING.md) | Protocol v2 rollout, invitations, card prompts, management, and validation |
| [Architecture](ARCHITECTURE.md) | Components, request flow, channel admission, session behavior, limits, and trust/storage |
| [iOS](ios/README.md) | App build and setup, USB/NFC security keys, lifecycle, tests, and App Store Connect uploads |
| [Example client configuration](examples/client.toml) | Desktop provider and timeout settings |
| [Example server configuration](examples/server.toml) | Relay listen address, storage, and channel-creation policy |

## Get started

Desktop clients run on macOS and Linux with GnuPG 2.4 or 2.5. Building from source
requires Rust 1.96+. Card providers need native scdaemon; password providers need
native Pinentry. Relay-only hosts do not need GnuPG.

1. [Install release binaries](USAGE.md#install-release-packages) or
   [build from source](USAGE.md#requirements-and-build).
2. [Run a relay](USAGE.md#1-run-a-relay), exposed through TLS for remote use.
3. [Pair each device in a channel](USAGE.md#2-pair-devices-in-a-channel).
4. [Enable the providers you need and start each daemon](USAGE.md#3-enable-the-services-each-device-will-provide).
5. [Configure the requesting machine's GPG adapters](USAGE.md#4-connect-the-requesting-devices-agent)
   and [sign or decrypt](USAGE.md#sign-and-decrypt).

Relay and clients must use matching builds of protocol `hibiki/2`. The desktop
daemon starts local providers immediately, including while the relay is offline;
remote providers join the race independently. Card access
supports discovery, public-key reading, signing, and decryption; PIN changes,
key writing/generation, and raw APDU commands are rejected.
See [session behavior and limits](ARCHITECTURE.md#session-behavior-and-limits).

## Development and testing

Tests require Python 3 and Git in addition to the build requirements.

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo build --locked --workspace
python3 tests/server.py
python3 tests/integration.py
python3 tests/mobile.py
python3 tests/tui.py
python3 tests/performance.py
```

CI runs on Ubuntu 24.04 and macOS. Integration tests use temporary identities and GnuPG homes, controlled stdio Pinentry processes, and an OpenPGP Card emulator. Real GnuPG exercises card learning, RSA signing and decryption, Git signing, password races and retries, cancellation, revocation, disconnects, and process cleanup.

Emulation does not replace hardware testing. Validate PIN retries, touch requirements, card removal, reader contention, and interrupted operations on real test cards on each target platform, respecting the card's PIN retry limit.

For package builds, CI workflows, and release publishing, see
[Build and publish releases](USAGE.md#build-and-publish-releases).
