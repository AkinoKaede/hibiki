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
3. A immediately starts its local scdaemon and opens all enabled remote candidates
   in parallel. Each independently checks for the requested card and prompts if needed.
   Public-key replies may come from iOS registration without selecting an executor.
   The first candidate ready for the target wins the private operation.
4. When input is requested, enabled Pinentry providers race to answer. C may win;
   the other prompts close. The answer returns to A, whose agent passes the card
   PIN to the selected card session on B.
5. B's native scdaemon performs the private operation on the card. Its response
   returns through A's daemon and adapter to the native agent and GPG caller.

Both provider services are enabled by default and are independently configurable
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
single-use initialization invitation containing its PSK; the first device claims
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

**Card access.** Each adapter owns a persistent pool of scdaemon candidates. Enabled backends start even without a card. Offline members join on return; busy devices are retried without taking a session from another caller. Local startup never waits for a relay request. Metadata sources and private executors are separate: a registered iOS public key does not dismiss desktop insertion prompts.

Desktop readiness requires the actual target card/key. Insertion prompts use native Pinentry `CONFIRM` independently of the exported password service. Public metadata queries pause card probing without closing or recreating an unanswered insertion prompt. Confirming without the matching card repeats the prompt; desktop Pinentry Cancel cancels the entire operation; RESET/RESTART or a new adapter session permits another attempt. On iOS, × is the only cancel control and cancels the entire operation regardless of USB presence. Public queries and target refinement cannot resurrect a rejected operation. For iOS, a USB-only target must be inserted and checked. A target registered with NFC can confirm before entering its PIN and tapping; a matching connected USB card takes precedence when preparing a dual-interface key. Transport is fixed after preparation, and the physical key is verified before any PIN is sent.

Winning preparation closes other insertion prompts while retaining their processes and connections. `SETDATA` is validated and bounded at the caller, then bundled with a single private `Execute` to the winner. No failed, canceled, or unknown private result is automatically retried on another device. `RESET`/`RESTART` clear selection and staged data while keeping connections. Adapter exit, channel exit/deletion, and revocation close all affected candidates. Each provider grants one exclusive scdaemon session; native processes run with `--server` in `$XDG_DATA_HOME/hibiki/scdaemon`, without touching another agent's scdaemon or reader lease.

**Password entry.** Each `GETPIN`, `CONFIRM`, or `MESSAGE` request starts a fresh race among enabled local and remote providers, including devices that return online before the command deadline. The first complete successful response wins. A failed input candidate is eliminated while remaining candidates can still succeed. Standard cancellation (`GPG_ERR_CANCELED`, 99, or `GPG_ERR_FULLY_CANCELED`, 198) terminates the race immediately, closes every other prompt, and returns only the original terminal error without rewriting its code or source. iOS × returns CANCELED regardless of USB presence. A later explicit command starts a new race. Losing processes are closed, and their partial input is discarded.

The native agent or card validates the password. A retry starts a new race; Hibiki never tries the losing candidates' passwords. Answers go only to the requester. Multiple Pinentry inquiries are serialized upstream, with each answer routed back to its original candidate.

**Transport and lifecycle.** The agent starts adapters over stdio; scdaemon's `--multi-server` mode also accepts additional agent connections through a private local Unix socket. Hibiki-to-native-program connections use stdio. The adapters reach the local daemon through its private Unix socket. Assuan inquiries preserve their parameters, binary data, percent escapes, and native error codes.

- In `--multi-server` mode, `GETINFO socket_name` advertises the adapter's local socket, with a separate daemon session for each connection. The socket uses mode 0600 in a private 0700 runtime directory; the primary pipe owns its lifetime and closes all secondary sessions on exit. Plain stdio mode still returns no socket. Native provider sockets are never forwarded, and each card provider retains its exclusive session limit.
- Card discovery, public-key reading, signing, and decryption are supported. PIN changes, key writing, key generation, and raw APDU commands are rejected on both ends.
- Each active command has a 120-second default timeout, configurable from 1 to 3600 seconds. Idle time does not consume the next command's deadline.
- Caller exit, timeout, revocation, or channel deletion cancels pending work and closes affected backends. Offline members can join a waiting operation before its original deadline; the first success cancels every other queued copy. Relay reconnection preserves live callers and uses new encrypted sessions.
- An execution claim is durable: if execution started and its result was lost, Hibiki reports failure/unknown result and never automatically repeats the private command. Reselection requires an explicit new card selection or reset.
- The relay persists operation IDs, deadlines, targets, and execution states, not PINs, plaintext command data, or results. Queue limits are 128 operations per caller or target and 4096 in total. Pending work survives a relay restart only when the live caller resumes it; restarting the caller daemon does not restore vanished calls.
- Local providers start immediately, even before the first relay connection. Local discovery, password answers, and selected-card commands never wait for relay operation registration or completion; remote candidates prepare concurrently. Offline local access uses the saved channel membership proof; received revocations and channel deletion still cancel affected sessions.
- Relay operation metadata and durable execution claims apply to remote candidates. Local card commands run once on the bound native session; a lost private-operation response is never automatically replayed.

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

The protocol identifier is **`hibiki/2`** and the WebSocket path is **`/hibiki`**. It includes relay policy discovery and pending-request rejection, withdrawal and status queries. Network messages use Protocol Buffers. Relay and clients may use different application releases while supporting the same baseline and negotiating extensions; unpublished Postcard network formats are not supported. See [the compatibility contract](PROTOCOL.md).

## Protocol v2 and measurements

The WebSocket path remains `/hibiki`. Noise setup is followed by `OpenService` / `ServiceOpened`, combining verified trust, service capability and eager backend opening. `PrepareCard` has its own identifier and Waiting/Ready/Unavailable state; `CancelPreparation` cancels only that preparation. Ordinary connected queries use one Input and one bounded OutputBatch, without queue registration. Inquiry boundaries flush batches immediately. Private `Execute` carries the operation ID, staged input and command; the receiver atomically claims authorization and persists its anti-replay record before execution.

The provider persists completion before returning the final result. The caller completes its end registration asynchronously and idempotently after receiving that result. Operation status monitoring has an independent task and cannot block Assuan reads or writes. Channel snapshots combine membership and online peers; online/offline notifications trigger discovery, and reconnect resynchronizes state.

The relay uses shared authority locks per channel for routing and ordinary control
requests. Membership changes take exclusive authority in that channel; unrelated
channels continue processing. Operation transitions are serialized per operation
ID, with a separate admission lock enforcing queue limits across channels.
Subscription checks and relay enqueue are atomic with executor registration and
disconnect. Membership and administrator access checks still run on every relay.

Each authenticated connection reads and writes independently of its request
workers. Independent controls can reply out of order and are matched by request
ID; callers must await a response before sending work that depends on it. Relay
frames retain arrival order within each channel/peer/session, including empty
close frames. A connection permits at most 128 in-flight workers and 8 MiB of
retained inbound wire bytes, in addition to bounded output queues. Overload closes
the connection; disconnect cancels and drains workers before unregistering its
executor. Heartbeats and the 45-second receive deadline continue during slow work.

A matching authenticated outer Relay frame with empty data cancels an existing peer/channel/session, including a handshake interrupted before encrypted Close is available. Empty frames cannot open a session; routing and membership checks still apply. This also releases a backend opened concurrently with caller cancellation.

Ping uses its own Noise-authenticated `PingOpen`/`PingOpened` session and random matching Ping/Pong nonces, never a provider slot. CLI, TUI and iOS report setup separately from RTT, with 1–20 samples and a five-second deadline per sample. It measures the encrypted path through the relay, not ICMP or a direct network route.

Trace metrics contain only message kinds/counts; session and adapter summaries contain elapsed durations. They never contain Assuan bodies, PINs, PSKs or private input. `tests/performance.py` adds 0/50/100/200 ms RTT to an isolated simulated-card setup. Its stable gate is five ordinary queries = five request messages + five result messages; timings are diagnostic rather than machine-dependent pass criteria.

Management uses a separate authenticated connection without Announce, so it cannot replace a daemon or become a service executor. Rename signs an identity update with unchanged public keys, device ID and verification words; only a device can rename itself. TUI refreshes every two seconds, preserves timestamped cached data when offline, and revalidates request identities before mutations.

### Approval-chain authority

Approval records form a directed chain from the channel founder. An active member
can revoke its direct or indirect descendants immediately. After **30 days since
its current admission**, it may also revoke its own approver or another ancestor.
Leaving and joining again restarts that waiting period. Other branches and
self-revocation remain disallowed; use Leave for self-removal. The relay checks
its own clock as well as the signed event; backdated admissions cannot accelerate
the waiting period.

Revocation affects **only the named device by default**. Use
`hibiki channel revoke NAME DEVICE_ID --subtree` to explicitly remove that device
and its approval subtree. Subtree revocation is restricted to descendants so it
cannot accidentally include the caller. Revoked identities cannot rejoin. An
ordinary revocation leaves descendants active, and ancestry remains verifiable
through departed intermediaries. Readmission must not reverse ancestry or create
a cycle.

iOS and TUI offer separate actions for one device and an entire subtree. The
confirmation lists all affected active devices with full IDs and defaults to
cancel. A changed membership revision invalidates the confirmation; submission
never retries automatically against a changed tree. Ancestor details display the
date when reverse revocation becomes available. JSON includes `approved_by`,
`approver_name`, `can_revoke`, `reverse_revoke_available_at`, `revocation_subtree`
and `revoked_by_server`.

The local server administrator can revoke **any** device, including the founder,
without approval-chain or age restrictions:

```sh
hibiki-server channel revoke NAME DEVICE_ID
hibiki-server channel revoke NAME DEVICE_ID --subtree
```

This is a persistent relay access revocation, independent of member-signed history.
It blocks routing, announcements, admission and management mutations, cancels
related queued operations atomically, and disconnects affected executors within
the one-second administration watcher interval. Other members see “Revoked by
server”. The administrator does not possess members’ signing keys and does not
rewrite their signed history. Local operations while disconnected remain available;
server revocation cannot erase another machine’s offline keys or cached history.
