# Hibiki network protocol

The first published `hibiki/2` uses Protocol Buffers over binary WebSocket messages
at `/hibiki`. One WebSocket message contains one `Envelope`, without an extra
length prefix. The relay routes Noise packets as opaque bytes. The Noise XX
handshake and its Postcard-encoded prologue remain unchanged; authenticated
transport plaintext contains a Protobuf `Fragment`, whose reassembled payload is
one Protobuf `PrivateMessage`.

## Schema and codecs

The `hibiki.v2` package is split by function in `lib/proto`:

| File | Responsibility |
| --- | --- |
| `membership.proto` | Device certificates, genesis, joins and signed membership history |
| `operation.proto` | Service kinds, queued operations and target states |
| `control.proto` | Management requests, replies and errors |
| `relay.proto` | WebSocket greeting, authentication, routing and notifications |
| `session.proto` | Encrypted service/Ping setup, Assuan messages and fragments |

`hibiki_lib::wire::{encode, encode_secret, decode}` converts business types to
Protobuf. Cargo generates Rust types with `prost-build` and bundled host `protoc`;
no system Protobuf installation is needed, including for iOS cross-compilation.
The desktop, relay and iOS Rust framework share this codec.

`hibiki_lib::{encode, encode_secret, decode}` remains the separate Postcard codec
for local IPC, identities, trust files, database blobs, invitations, signing inputs
and hashes. Never sign or hash re-encoded Protobuf as a replacement for a v1
preimage: Protobuf is not a canonical serialization. Network conversions preserve
v1 certificates, signatures, history hashes and trust checkpoints.

## Compatibility contract

The schema, message behavior and limits at the first publication are the
`hibiki/2` baseline. Application release numbers need not match. A newer server,
desktop client or iOS client must continue supporting this baseline for as long
as it advertises `hibiki/2`. A same-major upgrade requires no simultaneous rollout.
The earlier unpublished Postcard network format is unsupported.

Within this major version:

- Add fields with new numbers and safe defaults; do not make new fields mandatory
  for baseline operations. Keep existing field types, meanings and default behavior.
- Never reuse field numbers, enum values or their names. Reserve numbers and names
  when retiring extensions; do not remove baseline behavior.
- Use explicit `oneof` message variants. Scalar enum zero means unspecified, never
  a valid operation, service or authorization state.
- Ignore unknown ordinary fields. Reject missing required messages, unknown enum
  values and unsupported command, private-message or membership-action variants.
  A peer must not send a new message variant before negotiating its capability.
- Keep all v1 signed structures and their Postcard encoding and semantics fixed.
  Changes to permission, membership or security semantics that cannot safely retain
  baseline behavior require a new protocol major version. Protobuf field tolerance
  is not permission to ignore a new security requirement.

The baseline requires no extension capability strings. Add a stable capability
name only alongside the code that gates all its sends and effects. Unsupported
features use baseline behavior where possible or fail explicitly; never replay
private operations as a compatibility fallback.

Card preparation rejection is an additive failure detail: `CardPreparationUnavailable.rejected`
(field 1, default false) identifies explicit whole-operation cancellation during card preparation.
Updated requesters return Assuan cancellation immediately. During password entry,
standard Assuan cancellation errors 99 (`GPG_ERR_CANCELED`) and 198
(`GPG_ERR_FULLY_CANCELED`) both cancel the entire race. Native terminal errors
retain their original code and source. Baseline requesters ignore the card rejection
field and retain unavailable/timeout behavior; the canceling provider still cannot
execute the operation. Upgrade both endpoints for immediate rejection reporting.
Existing baseline fields, variants and byte fixtures remain unchanged.

## Capability negotiation

Relay setup uses `Hello.capabilities` for the server declaration and
`Authenticate.capabilities` for the client declaration. Both lists are sorted and
deduplicated before signing the Postcard tuple
`(version, nonce, device_id, server_capabilities, client_capabilities)` under
`server-auth/v2`. The server verifies that tuple against its actual declaration
before registering the client. `Authenticated.capabilities` returns the
intersection; the client checks it against the intersection it computed.
Declarations are limited to 64 entries of 1–128 ASCII letters, digits or `._/-`.
A missing list means empty and supports all baseline operations.

Peer setup negotiates independently of the relay. After Noise authenticates both
pinned keys, the initiator offers capabilities in `OpenService` or `PingOpen`.
`ServiceOpened` or `PingOpened` returns the intersection with the responder's
supported capabilities. The initiator rejects unoffered selections. Lists are
protected inside the Noise session; relay capabilities do not authorize a peer
extension. This adds no round trip to service or Ping setup.

## Ignoring an input request

`pinentry-ignore-v1` negotiates `SessionOutput.ignored` (oneof field 4), containing
`SessionOutputIgnored.request` (uint64 field 1). It is a terminal, device-local
withdrawal for the named active Pinentry request, not an Assuan response. Only
Pinentry sessions may send it; the request ID must match an active command with
no outstanding inquiry. The requester discards partial input, removes that
candidate and continues waiting for the others. The provider releases its queue
claim. If every candidate exits, the requester returns an aggregate failure;
a later explicit caller command may start a new race.

Ignore is never forwarded to gpg-agent. It has **no compatibility fallback** to
NO_DATA, CANCELED, or a legacy failure message. Both peers must negotiate the
capability before sending or accepting it; unsupported peers fail explicitly.
Do not reintroduce error-code aliases for Ignore. Ordinary CANCELED (99) and
FULLY_CANCELED (198) retain whole-operation cancellation semantics.

## Bounds and private data

Existing bounds remain: WebSocket envelopes up to 4 MiB, reassembled encrypted
payloads up to 2 MiB, plaintext fragments of 1–48 KiB, Noise packets up to 65,535
bytes, and the existing Assuan line/batch limits. A frame also has a maximum of 65,536 nested messages and 100 nesting levels.
Duplicate singular fields or competing oneof selections are rejected before
decoding, so a replacement cannot discard or reallocate an uncleared secret.
Required message presence,
32-byte keys/digests, 64-byte signatures and card targets are checked during wire
conversion; trust and authorization are still verified by the existing logic.

Private encoding allocates an output buffer of exactly the encoded length.
Generated intermediate messages and partially decoded messages sit behind
`Zeroizing` guards, including failure paths. Assuan payloads remain redacted and
secret-bearing message bodies are never logged.

## Baseline tests

`lib/tests/fixtures/wire-v2.descriptor` freezes field numbers, types, oneof
membership and enum values across all five schemas. `wire-v2.hex` freezes bytes for
all network variants. `wire-identity.postcard` contains only a synthetic test
identity; it also anchors legacy storage and signed preimages. Do not regenerate
published fixtures to silence a compatibility failure.

Tests verify both directions with an independent baseline decoder and a future
schema containing an additional optional field, negotiation with differing or
missing capabilities, authenticated declarations, trust/hash preservation,
malformed messages and encryption/fragment boundaries. Integration suites exercise
mixed desktop/mobile roles, revocation, cancellation, signatures and PIN inquiries.
