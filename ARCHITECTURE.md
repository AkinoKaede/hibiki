# Hibiki architecture

[Overview](README.md) · [Usage guide](USAGE.md) · [iOS guide](ios/README.md)

Hibiki forwards the Assuan interfaces used by scdaemon and Pinentry. The requesting
machine keeps its native `gpg`, `gpg-agent`, and Git workflow; participating devices
provide card access and password input over end-to-end encrypted sessions.

## Contents

- [Components](#components)
- [Request flow](#request-flow)
- [Channels and admission](#channels-and-admission)
- [Session behavior and limits](#session-behavior-and-limits)
- [Trust and storage](#trust-and-storage)

## Components

| Component | Responsibility |
| --- | --- |
| [`lib/`](lib/) (`hibiki-lib`) | Shared wire formats, Assuan parsing, identities, Noise encryption, and membership verification |
| [`core/`](core/) (`hibiki-core`) | Shared desktop/mobile transport, trust storage, channel management, peer sessions, and operation lifecycle |
| [`client/`](client/) (`hibiki`) | Desktop CLI and daemon, local IPC, diagnostics, and native scdaemon/Pinentry providers |
| `hibiki-scdaemon` / `hibiki-pinentry` | Stdio adapters started by the requesting machine's `gpg-agent`; connect to the local daemon |
| [`server/`](server/) (`hibiki-server`) | Device authentication, channel admission, SQLite persistence, operation metadata, and encrypted WebSocket relay |
| [`mobile/`](mobile/) (`hibiki-mobile`) | UniFFI bridge, mobile password requests, OpenPGP card operations, and public card registry |
| [`ios/`](ios/README.md) | SwiftUI interface, Keychain storage, CryptoTokenKit wired access, and Core NFC access |

The protocol library contains no sockets, processes, or databases. Desktop and
mobile clients share the transport and trust core; their provider implementations
handle platform-specific input and card access. The iOS app does not run GnuPG or
a background daemon.

## Request flow

For a commit signed on laptop A using a card on desktop B and PIN entry on device C:

1. Git invokes A's native `gpg`; `gpg-agent` starts the configured Hibiki stdio adapters.
2. The adapters connect to A's daemon through its private Unix socket and use the
   channel selected when that adapter session started.
3. A discovers enabled card providers through encrypted peer sessions relayed over
   WebSocket. It selects B's matching card and keeps that card session bound to B.
4. When input is requested, enabled Pinentry providers race to answer. C may win;
   the other prompts close. The answer returns to A, whose agent passes the card
   PIN to the selected card session on B.
5. B's native scdaemon performs the private operation on the card. Its response
   returns through A's daemon and adapter to the native agent and GPG caller.

Both provider services are disabled by default and are independently configurable
on every device. A device may request services with both providers disabled, or
provide either service or both. The requester can also participate as a local
provider. For software keys, only password entry needs to be forwarded; the
private operation stays on the requesting machine.

On iOS, native UI and card transports replace the desktop native processes. The
app receives requests while in the foreground. NFC registration stores public
card information; private operations require confirmation unless the wired card
is already connected. Card identity is verified before sending the PIN, and PIN
entry precedes the NFC tap for signing or decryption. See the
[iOS lifecycle and hardware guide](ios/README.md) for platform details.

## Channels and admission

A channel is the membership and service-sharing boundary. Channel creation is
reserved for the relay administrator by default. The administrator issues a
single-use initialization invitation and a separate PSK; the first device claims
the channel without existing-member approval. Later devices use member invitations,
prove knowledge of the PSK, and wait for an active member to approve their identity.

Members compare the joining device's request ID and all 24 public-key verification
words before approval. These words identify a public key; they are not a recovery
phrase. Each device generates its own identity rather than copying another's files.
Approved members can use enabled services and approve additional members.

PSK rotation invalidates pending requests and preserves approved membership.
Revocation prevents that identity from rejoining the same channel; voluntary
leaving permits a new admission request. Administrator deletion closes affected
sessions, and recreating the same channel name creates a new channel ID.
See [channel administration](USAGE.md#channel-administration) for commands.

## Session behavior and limits

**Card access.** Hibiki discovers enabled providers in parallel and selects the first OpenPGP Card matching the requested serial number or keygrip. Without a target, it selects the first available card. Once selected, card state, data, PIN inquiries, signing, and decryption stay on that backend until an explicit reset or card selection. A failure does not switch cards or replay a private operation.

Each device grants one exclusive scdaemon session at a time; busy devices reject additional sessions. Hibiki starts its own native scdaemon with `--server` in `$XDG_DATA_HOME/hibiki/scdaemon`. Reader settings can go in that directory's `scdaemon.conf`. It does not connect to existing agent/scdaemon sockets or terminate other services holding a reader.

**Password entry.** Each `GETPIN`, `CONFIRM`, or `MESSAGE` request starts a fresh race among enabled local and remote providers, including devices that return online before the command deadline. The first complete successful response wins. A canceled or failed window only eliminates that candidate; remaining candidates can still succeed. Losing processes are closed, and their partial input is discarded.

The native agent or card validates the password. A retry starts a new race; Hibiki never tries the losing candidates' passwords. Answers go only to the requester. Multiple Pinentry inquiries are serialized upstream, with each answer routed back to its original candidate.

**Transport and lifecycle.** The agent starts adapters over stdio; scdaemon's `--multi-server` mode also accepts additional agent connections through a private local Unix socket. Hibiki-to-native-program connections use stdio. The adapters reach the local daemon through its private Unix socket. Assuan inquiries preserve their parameters, binary data, percent escapes, and native error codes.

- In `--multi-server` mode, `GETINFO socket_name` advertises the adapter's local socket, with a separate daemon session for each connection. The socket uses mode 0600 in a private 0700 runtime directory; the primary pipe owns its lifetime and closes all secondary sessions on exit. Plain stdio mode still returns no socket. Native provider sockets are never forwarded, and each card provider retains its exclusive session limit.
- Card discovery, public-key reading, signing, and decryption are supported. PIN changes, key writing, key generation, and raw APDU commands are rejected on both ends.
- Each active command has a 120-second default timeout, configurable from 1 to 3600 seconds. Idle time does not consume the next command's deadline.
- Caller exit, timeout, revocation, or channel deletion cancels pending work and closes affected backends. Offline members can join a waiting operation before its original deadline; the first success cancels every other queued copy. Relay reconnection preserves live callers and uses new encrypted sessions.
- A selected card stays bound to its original device and serial. Reconnection restores confirmed selection and SETDATA preparation for commands not yet executed. An execution claim is durable: if execution started and its result was lost, Hibiki reports an unknown result and never automatically repeats the private command.
- The relay persists operation IDs, deadlines, targets, and execution states, not PINs, plaintext command data, or results. Queue limits are 128 operations per caller or target and 4096 in total. Pending work survives a relay restart only when the live caller resumes it; restarting the caller daemon does not restore vanished calls.
- The daemon currently needs a relay connection even when only local providers are used.

## Trust and storage

Devices authenticate with Ed25519 identities and establish `Noise_XX_25519_ChaChaPoly_BLAKE2s` sessions bound to the protocol, channel, device identities, and session ID. Signed membership histories and saved checkpoints detect rollback, identity substitution, and conflicting histories. Service discovery is encrypted too.

The relay can see membership, routing, timing, and ciphertext sizes, but cannot read Assuan traffic. It queues operation metadata for offline devices while the original caller is still waiting. Approved channel members can use enabled services and approve additional members.

Card private keys stay on the card; software private keys stay on the requesting device. PINs and passphrases pass through the input device and requester, and card PINs also reach the selected card provider. Hibiki clears secret buffers after use, does not cache passwords or enable Pinentry's external password cache, and keeps protocol bodies and secrets out of logs. Native agent caching still applies.

| Data | Location |
| --- | --- |
| Configuration | `$XDG_CONFIG_HOME/hibiki` (default `~/.config/hibiki`) |
| Identity and trust | `$XDG_DATA_HOME/hibiki` (default `~/.local/share/hibiki`) |
| Local IPC | `$XDG_RUNTIME_DIR/hibiki`, or a private per-user temporary directory |

Private files use mode `0600` and directories use `0700`. Back up identity and trust records together.

The protocol identifier is **`hibiki/1`** and the WebSocket path is **`/hibiki`**. It includes relay policy discovery and pending-request rejection, withdrawal and status queries. Relay and clients must use matching builds; pre-release formats are not supported.
