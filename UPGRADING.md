# Upgrading to Hibiki protocol v2

The first published `hibiki/2` uses Protocol Buffers; the endpoint remains `/hibiki`. If running the earlier unpublished Postcard format, upgrade the relay, desktop daemon/adapter and iOS Rust framework/app together once. After that, application releases may differ within the same protocol major version: baseline behavior remains supported and extensions require capability negotiation. Other protocol majors are rejected. See [the compatibility contract](PROTOCOL.md). Stop active signing/decryption before replacing binaries, then restart daemons. Do not retry a private operation whose result is unknown; first check whether the caller already received or recorded it.

Existing device identities and card registrations remain usable. Trusted channels must satisfy the approval-chain rule described below. New self-rename membership events require v2 peers. Invitation versions are independent: old `hibiki-v1:` and `hibiki-init-v1:` imports still work, while newly exported `hibiki-psk-v1:` invitations contain their PSK. Old clients cannot import the new envelope. Bootstrap invitations remain single-use and membership approval still requires all 24 verification words. PSK rotation invalidates pending requests and old credentials without removing approved members.

There is no `--include-psk` option. Keep the invitation securely or create with a chosen PSK (`--psk-file` / `--prompt-psk`) if you will generate invitations later. Import prompts for a missing PSK and rejects supplying one alongside an embedded PSK. Hibiki does not persist it.

Desktop insertion prompts are native Pinentry confirmation dialogs owned by the card service. They work even with password sharing disabled; a GUI-capable native Pinentry must be available to show them. Confirmation without the matching physical card repeats the prompt. Unanswered prompts now survive public queries without flashing closed and reopening. On iOS, the explicit Cancel button always cancels the operation. Closing with × cancels the operation with USB inserted and only dismisses this device without USB. Desktop Pinentry Cancel dismisses this device. Explicit cancellation returns immediately instead of waiting for the operation timeout; canceled card preparation requires RESET/RESTART or a new adapter session before retrying. The adapter retains candidate backends until its session ends, so they can hold their exclusive reader lease for longer than before. Busy candidates never steal another session. RESET/RESTART release selection and staged input, not the candidate pool. Local capabilities keep working when the relay is unavailable. Native scdaemon stays alive across card rediscovery and RESTART, preserving its card authentication state and the gpg-agent PINCACHE exchange. Explicit RESET, card removal and native card PIN policies still apply; Hibiki does not add a plaintext PIN cache.

`hibiki tui` provides interactive management without announcing another executor or replacing a running daemon. It does not restart system services. Saved service changes require a daemon restart; the default channel affects new adapter sessions. `hibiki ping DEVICE_ID --channel NAME` (also `hibiki device ping`) measures encrypted peer RTT through the relay without opening card/password services. CLI ID arguments accept unique hexadecimal prefixes of at least six characters. Exact channel names remain supported; ambiguous prefixes fail with the full candidates.

iOS Members now opens device details with complete identity, words, status, Ping and an explicit revocation confirmation. Settings can rename this device. Security-key registration uses the cardholder name by default when available; a complete AID remains the identity used for card matching. USB-only readiness requires the actual card, while a target registered for NFC may confirm before PIN entry and tap. Wrong cards never receive a PIN.

## Reproducible performance check

Run `python3 tests/performance.py` after building. It uses isolated software cards and a TCP delay proxy, adding half of the configured RTT on each requester-link direction. Each established public query must emit exactly one request and one result message; five queries are the stable CI gate. Timings include process scheduling and emulator work and are reports, not portable pass thresholds. Cold means a fresh adapter/candidate session with already running daemons, not a cold OS cache.

Example on macOS, 2026-10-05:

| Added RTT | Cold card session | Mean steady query | SETDATA | Sign + PIN inquiry | Query frames (5 queries) |
| --- | ---: | ---: | ---: | ---: | --- |
| 0 ms | 377.45 ms | 9.85 ms | 0.85 ms | 93.43 ms | 5 requests + 5 results |
| 50 ms | 319.64 ms | 61.19 ms | 1.77 ms | 448.61 ms | 5 requests + 5 results |
| 100 ms | 456.01 ms | 117.66 ms | 1.78 ms | 550.45 ms | 5 requests + 5 results |
| 200 ms | 823.88 ms | 216.51 ms | 1.09 ms | 998.11 ms | 5 requests + 5 results |

| Local path with same software card | Cold card session | Mean query | Sign + PIN inquiry |
| --- | ---: | ---: | ---: |
| Native stdio fixture | 316.50 ms | 0.19 ms | 33.30 ms |
| Hibiki local adapter; relay paused | 296.82 ms | 1.44 ms | 32.61 ms |

Hibiki adds local IPC, validation and selection overhead; it does not claim zero overhead or identical native timings. Private signing retains authorization, PIN inquiry and durable completion round trips. This report compares the new paths with the native fixture, not a measured historical v1 build.

## Validation

The isolated suites cover desktop GnuPG/Git signing and decryption, native Pinentry races, all-candidate insertion, canceled/busy/offline candidates, local operation under a paused relay, request revocation/deletion and no automatic private replay. Mobile integration exercises real GnuPG with software RSA/ECC cards, both Ping directions, USB confirmation without insertion, NFC selection and wrong-card rejection before PIN VERIFY. Rust tests cover invitation parsing/secrecy, identity rename, authorization and replay state, prefix ambiguity, presentation and stale TUI confirmations. PTY tests check keyboard navigation, resize, q/Ctrl-C restoration and external config edits.

Commands:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo build --locked --workspace --all-targets
python3 tests/server.py
python3 tests/integration.py
python3 tests/mobile.py
python3 tests/mobile_tls.py
python3 tests/tui.py
python3 tests/performance.py
bash ios/scripts/build-rust.sh Debug
bash ios/scripts/check-zh-localization.sh
```

The iOS framework builds for device arm64 and simulator arm64/x86_64. Simulator XCTest/UI tests require an ad-hoc-signed app for Keychain access (`CODE_SIGN_IDENTITY=- CODE_SIGNING_ALLOWED=YES`, with `ARCHS=arm64 ONLY_ACTIVE_ARCH=YES` on Apple Silicon). Unsigned builds can compile but do not validate Keychain-backed onboarding. Physical USB/NFC reader behavior, touch requirements and real-card PIN retry behavior still require hardware acceptance testing; software emulation and the simulator cannot certify them.

## Approval-chain policy change

Members may revoke descendants immediately, or ancestors after 30 days of their
current admission. Self and cross-branch revocations are rejected. Ordinary revoke
remains target-only; the new explicit `RevokeSubtree` signed action removes a
whole descendant branch. Confirmations bind the membership revision and must be
reviewed again after concurrent changes. Rejoining restarts the 30-day clock.

Legacy histories containing early ancestor, cross-branch or self revocations, or
reversed ancestry on readmission, fail verification under this policy. They are
not silently grandfathered, edited or migrated: recreate the channel and approve
members independently, retaining the old files for review. Histories satisfying
the policy require no conversion; ancestry and admission times derive from signed
events.

Server administrators have an independent `channel revoke NAME DEVICE_ID
[--subtree]` command. Its durable relay deny list is created automatically in the
existing database. It can target any member and does not rewrite member-signed
history or disable offline local keys. Administrator-revoked device IDs in channel snapshots are part of the published
v2 baseline and must be honored by every v2 component.
