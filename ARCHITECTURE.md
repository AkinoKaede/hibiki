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
| [`server/`](server/) (`hibiki-server`) | Device authentication, channel admission, SQLite persistence, operation metadata, and encrypted WebSocket forwarding |
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
app receives requests in the foreground and during a finite, system-granted
background execution allowance. Type-only local notifications route to pending
operations or channel join approvals; no APNs delivery is available after suspension.
Backgrounding releases hardware, and allowance expiration cancels the connection
synchronously. NFC registration stores public
card information; USB cards need no registration. Selected NFC cards skip extra
confirmation. After PIN entry, the provider checks USB before opening NFC, and
verifies the target identity before sending the PIN. See the
[iOS lifecycle and hardware guide](ios/README.md) for platform details.

## Channels and admission

A channel is the membership and service-sharing boundary. Channel creation is
reserved for the server administrator by default. The administrator issues a
single-use initialization invitation containing its own random key; the first device claims
the channel without existing-member approval. Later devices use member invitations,
consume an independent invitation key, and wait for an active member to approve their identity.

Members compare the joining device's request ID and all 24 public-key verification
words before approval. These words identify a public key; they are not a recovery
phrase. Each device generates its own identity rather than copying another's files.
Approved members can use enabled services and approve additional members.

Each invitation expires after 24 hours and is atomically consumed by one valid request. Pending requests do not expire with the key. Inviter departure invalidates its outstanding invitations and pending requests. Revoked identities and voluntary departures can rejoin after a fresh request and approval; approval ancestry is tracked per admission round, including returning founders. Administrator denial persists until readmission commits. Administrator deletion closes affected
sessions, and recreating the same channel name creates a new channel ID.
See [channel administration](USAGE.md#channel-administration) for commands.

## Session behavior and limits

**Card access.** Each adapter owns a persistent pool of scdaemon candidates. Enabled backends start even without a card. Opening a session and ordinary public discovery do not start insertion prompts. On iOS, `SERIALNO` probes USB first, then reports the user’s volatile NFC selection, or returns card-not-present. `SERIALNO --demand` probes for the requested USB card, uses a matching NFC selection, or asks for confirmation if that specific card is registered for NFC. It never prompts for an unknown or USB-only absent target. `PKSIGN`/`PKDECRYPT` starts physical preparation for the selected target. Each public discovery queries every candidate once. An offline or disabled device ends its participation in that round immediately; native errors are preserved while other online devices can still succeed. A targeted `KEYINFO` searches every device even if `SERIALNO` previously found an unrelated card. No-card results return to gpg-agent, which generates the numbered insertion `CONFIRM` from its shadow key. A new confirmation starts another discovery. Background reconnection permits later requests without holding the current query open. Local startup never waits for a server request. Metadata sources and private executors are separate: a registered iOS public key does not dismiss desktop insertion prompts.

Desktop readiness requires the actual target card/key. Insertion prompts require a known target serial number; a target without one is probed silently until it can be identified. Insertion prompts use native Pinentry `CONFIRM` independently of the exported password service. Public metadata queries pause card probing without closing or recreating an unanswered insertion prompt. Confirming without the matching card repeats the prompt; desktop Pinentry Cancel cancels the entire operation; RESET/RESTART or a new adapter session permits another attempt. On iOS, × is the only cancel control and cancels the entire operation regardless of USB presence. Public queries and target refinement cannot resurrect a rejected operation. The iOS Status page and Pinentry `CONFIRM` sheet share one optional NFC selection. It defaults to none, is not persisted, and skips additional NFC consent for that target without replacing physical verification. Selecting a card inside gpg-agent’s insertion confirmation lets its next ordinary `SERIALNO` discover that card. PIN entry cannot change the selection. On iOS, USB discovery supplies live public metadata without registration. Selected NFC cards and demand-confirmed NFC targets proceed to PIN entry without another confirmation. Once the PIN reply arrives, the chosen provider probes USB regardless of cached presence, then opens NFC only if USB has no matching card and the device supports NFC. This fallback does not require registration for a USB-discovered target. Serial, slot, keygrip and fingerprint are checked before PIN VERIFY on the same connection used for the private operation. Reader errors, cancellation and Bad PIN are terminal; no fallback occurs after verification starts.

Winning preparation closes other insertion prompts while retaining their processes and connections. `SETDATA` is validated and bounded at the caller, then bundled with a single private `Execute` to the winner. No failed, canceled, or unknown private result is automatically retried on another device. `RESET`/`RESTART` clear selection and staged data while keeping connections. Adapter exit, channel exit/deletion, and revocation close all affected candidates. Each provider grants one exclusive scdaemon session; native processes run with `--server` in `$XDG_DATA_HOME/hibiki/scdaemon`, without touching another agent's scdaemon or reader lease.

**Password entry.** Each `GETPIN`, `CONFIRM`, or `MESSAGE` request starts a fresh race among enabled local and remote providers, including devices that return online before the command deadline. The first complete successful response wins. A failed input candidate is eliminated while remaining candidates can still succeed. Standard cancellation (`GPG_ERR_CANCELED`, 99, or `GPG_ERR_FULLY_CANCELED`, 198) terminates the race immediately, closes every other prompt, and returns only the original terminal error without rewriting its code or source. iOS × returns CANCELED regardless of USB presence. A later explicit command starts a new race. Losing processes are closed, and their partial input is discarded.

The native agent or card validates the password. A retry starts a new race; Hibiki never tries the losing candidates' passwords. Answers go only to the requester. Multiple Pinentry inquiries are serialized upstream, with each answer routed back to its original candidate.

**Transport and lifecycle.** The agent starts adapters over stdio; scdaemon's `--multi-server` mode also accepts additional agent connections through a private local Unix socket. Hibiki-to-native-program connections use stdio. The adapters reach the local daemon through its private Unix socket. Assuan inquiries preserve their parameters, binary data, percent escapes, and native error codes.

- In `--multi-server` mode, `GETINFO socket_name` advertises the adapter's local socket, with a separate daemon session for each connection. The socket uses mode 0600 in a private 0700 runtime directory; the primary pipe owns its lifetime and closes all secondary sessions on exit. Plain stdio mode still returns no socket. Native provider sockets are never forwarded, and each card provider retains its exclusive session limit.
- Card discovery, public-key reading, signing, and decryption are supported. PIN changes, key writing, key generation, and raw APDU commands are rejected on both ends.
- Each active command has a 120-second default timeout, configurable from 1 to 3600 seconds. Idle time does not consume the next command's deadline.
- Caller exit, timeout, revocation, or channel deletion cancels pending work and closes affected backends. Offline password providers can join a waiting input operation before its original deadline; the first success cancels every other queued copy. Server reconnection preserves live callers and uses new encrypted sessions.
- An execution claim is durable: if execution started and its result was lost, Hibiki reports failure/unknown result and never automatically repeats the private command. Reselection requires an explicit new card selection or reset.
- The server persists operation IDs, deadlines, targets, and execution states, not PINs, plaintext command data, or results. Queue limits are 128 operations per caller or target and 4096 in total. Pending work survives a server restart only when the live caller resumes it; restarting the caller daemon does not restore vanished calls.
- Local providers start immediately, even before the first server connection. Local discovery, password answers, and selected-card commands never wait for server operation registration or completion; remote candidates prepare concurrently. Offline local access uses the saved channel membership proof; received revocations and channel deletion still cancel affected sessions.
- Server operation metadata and durable execution claims apply to remote candidates. Local card commands run once on the bound native session; a lost private-operation response is never automatically replayed.

## Trust and storage

Devices authenticate with Ed25519 identities and establish `Noise_XX_25519_ChaChaPoly_BLAKE2s` sessions bound to the protocol, channel, device identities, and session ID. Signed membership histories and saved checkpoints detect rollback, identity substitution, and conflicting histories. Service discovery is encrypted too.

The server can see membership, routing, timing, and ciphertext sizes, but cannot read Assuan traffic. It queues operation metadata for offline devices while the original caller is still waiting. Approved channel members can use enabled services and approve additional members.

Card private keys stay on the card; software private keys stay on the requesting device. PINs and passphrases pass through the input device and requester, and card PINs also reach the selected card provider. Hibiki clears secret buffers after use, does not retain plaintext passwords or enable Pinentry's external password cache, and keeps protocol bodies and secrets out of logs. Native agent caching still applies. For mobile cards, the requesting agent stores a versioned XChaCha20-Poly1305 PIN ciphertext; the mobile provider retains only zeroizing wrapping keys and validity metadata in memory. Authenticated cache identifiers bind the provider, channel, requester, card and key/PIN purpose, independently of USB/NFC transport or Assuan session. Background stop/start preserves wrapping keys; app/client recreation and disabling the card service destroy them. RESET invalidates the requester/channel, Bad PIN invalidates the card, and RESTART/public discovery preserve cache state. Publication is fenced against concurrent invalidation. Card identity and current signing PIN policy are checked before every VERIFY; cache hits never skip physical verification or allow private-operation replay. No cache data is persisted to disk or Keychain.

| Data | Location |
| --- | --- |
| Configuration | `$XDG_CONFIG_HOME/hibiki` (default `~/.config/hibiki`) |
| Identity and trust | `$XDG_DATA_HOME/hibiki` (default `~/.local/share/hibiki`) |
| Local IPC | `$XDG_RUNTIME_DIR/hibiki`, or a private per-user temporary directory |

Private files use mode `0600` and directories use `0700`. Back up identity and trust records together.

The protocol identifier is **`hibiki/3`** and the WebSocket path is **`/hibiki`**. It includes server policy discovery and pending-request rejection, withdrawal and status queries. Network messages use Protocol Buffers. Server and clients may use different application releases while supporting the same baseline and negotiating extensions; unpublished Postcard network formats are not supported. See [the compatibility contract](PROTOCOL.md).

## Protocol v2 and measurements

The WebSocket path remains `/hibiki`. Noise setup is followed by `OpenService` / `ServiceOpened`, combining verified trust, service capability and eager backend opening. `PrepareCard` has its own identifier and Waiting/Ready/Unavailable state; `CancelPreparation` cancels only that preparation. Ordinary connected queries use one Input and one bounded OutputBatch, without queue registration. Inquiry boundaries flush batches immediately. Private `Execute` carries the operation ID, staged input and command; the receiver atomically claims authorization and persists its anti-replay record before execution.

The provider persists completion before returning the final result. The caller completes its end registration asynchronously and idempotently after receiving that result. Operation status monitoring has an independent task and cannot block Assuan reads or writes. Channel snapshots combine membership and online peers; online/offline notifications trigger discovery, and reconnect resynchronizes state.

The server uses shared authority locks per channel for routing and ordinary control
requests. Membership changes take exclusive authority in that channel; unrelated
channels continue processing. Operation transitions are serialized per operation
ID, with a separate admission lock enforcing queue limits across channels.
Subscription checks and enqueueing forwarded frames are atomic with executor
registration and disconnect. Membership and administrator access checks still
run on every forwarded frame.

Each authenticated connection reads and writes independently of its request
workers. Independent controls can reply out of order and are matched by request
ID; callers must await a response before sending work that depends on it. `Relay`
frames retain arrival order within each channel/peer/session, including empty
close frames. A connection permits at most 128 in-flight workers and 8 MiB of
retained inbound wire bytes, in addition to bounded output queues. Overload closes
the connection; disconnect cancels and drains workers before unregistering its
executor. Heartbeats and the 45-second receive deadline continue during slow work.

A matching authenticated outer `Relay` frame with empty data cancels an existing peer/channel/session, including a handshake interrupted before encrypted Close is available. Empty frames cannot open a session; routing and membership checks still apply. This also releases a backend opened concurrently with caller cancellation.

Ping uses its own Noise-authenticated `PingOpen`/`PingOpened` session and random matching Ping/Pong nonces, never a provider slot. CLI, TUI and iOS report setup separately from RTT, with 1–20 samples and a five-second deadline per sample. It measures the encrypted path through the server, not ICMP or a direct network route.

Trace metrics contain only message kinds/counts; session and adapter summaries contain elapsed durations. They never contain Assuan bodies, PINs, invitation keys or private input. `tests/performance.py` adds 0/50/100/200 ms RTT to an isolated simulated-card setup. Its stable gate is five ordinary queries = five request messages + five result messages; timings are diagnostic rather than machine-dependent pass criteria.

Management uses a separate authenticated connection without Announce, so it cannot replace a daemon or become a service executor. Rename signs an identity update with unchanged public keys, device ID and verification words; only a device can rename itself. TUI refreshes every two seconds, preserves timestamped cached data when offline, and revalidates request identities before mutations.

### Approval-chain authority

Approval records form a directed chain from the channel founder. An active member
can revoke its direct or indirect descendants immediately. After **30 days since
its current admission**, it may also revoke its own approver or another ancestor.
Leaving and joining again restarts that waiting period. Other branches and
self-revocation remain disallowed; use Leave for self-removal. The server checks
its own clock as well as the signed event; backdated admissions cannot accelerate
the waiting period.

Revocation affects **only the named device by default**. Use
`hibiki channel revoke NAME DEVICE_ID --subtree` to explicitly remove that device
and its approval subtree. Subtree revocation is restricted to descendants so it
cannot accidentally include the caller. Revoked identities can rejoin with a valid unused invitation, a fresh request and new approval. An
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

This is a persistent server access revocation, independent of member-signed history.
It blocks routing, announcements, admission and management mutations, cancels
related queued operations atomically, and disconnects affected executors within
the one-second administration watcher interval. Other members see “Revoked by
server”. The administrator does not possess members’ signing keys and does not
rewrite their signed history. Local operations while disconnected remain available;
server revocation cannot erase another machine’s offline keys or cached history.
