# HIbiki for iOS

SwiftUI client for iOS 18 and later. Bundle identifier: `com.akinokaede.hibiki`.

The app uses the same Rust authentication, signed channel histories, Noise sessions,
and Assuan protocol as the desktop client. It provides native password entry and
OpenPGP card access through wired connections (CryptoTokenKit) or NFC (Core NFC). It does not
run GnuPG or a background daemon on iOS.

## Build

Requires Xcode with the iOS SDK, Rust 1.96+, Python 3, and the three Apple targets:

```sh
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
./ios/scripts/build-rust.sh Debug
open ios/HIbiki.xcodeproj
```

Select the shared **HIbiki** scheme. The checked-in Xcode project requires no
third-party project generator. After adding source files, regenerate it with:

```sh
python3 ios/scripts/generate-project.py
```

`build-rust.sh` generates UniFFI Swift bindings and `HIbikiCore.xcframework`; these
are build artifacts and are not committed. Re-run it after Rust changes. Use
`./ios/scripts/build-rust.sh Release` before an Archive/Release build. Both Debug and Release accept `ws://` and `wss://` relays. TLS certificate
validation is enabled by default.

Choose your own development team in Xcode to run on a physical device. Enable
NFC Tag Reading for the matching App ID and provisioning profile. The app declares
`com.apple.security.smartcard`, NFC `TAG` access, and OpenPGP application ID
`D27600012401`. No signing team or credentials are stored in this repository.

Unsigned verification:

```sh
xcodebuild -project ios/HIbiki.xcodeproj -scheme HIbiki \
  -destination 'generic/platform=iOS Simulator' CODE_SIGNING_ALLOWED=NO build
xcodebuild -project ios/HIbiki.xcodeproj -scheme HIbiki \
  -destination 'generic/platform=iOS' CODE_SIGNING_ALLOWED=NO build
```

## Pairing

1. The default relay is `wss://hibiki.akinokaede.com/hibiki`. Enter a device name
   and use the same relay as your computers. Plaintext `ws://` is accepted without
   a switch. Under the collapsed **Advanced** section, **Skip TLS Certificate
   Validation** disables certificate trust, hostname and validity checks for TLS
   when explicitly enabled. It is off by default and does not affect plaintext
   connections. The previous Debug plaintext preference does not enable it.
2. Create a channel, or paste a `hibiki-v1:` / `hibiki-init-v1:` invitation and
   enter the separately shared PSK.
3. For member invitations, compare **all 24 public-key words and the request ID**
   on an existing member before approving. The words are public identity data,
   not a recovery phrase. Pending requests expire after ten minutes.
4. Enable Password Entry and/or OpenPGP Card. Both start disabled. On the
   requesting computer, configure the HIbiki adapters as described in the root
   README. The app can approve members, share invitations, rotate PSKs, revoke
   identities, and leave channels.

## Security Keys

The OpenPGP application must already contain your keys. Import its public OpenPGP
certificate on the requesting computer. The app does not create or import private
keys, change PINs, reset the key, or expose remote raw APDU commands.

The registration form shows only the other transport's support switch: **NFC
support** when reading over a wired connection, or **Wired connection support** when reading over NFC. It is
on by default; turn it off for keys without that interface. This is a declared
capability, not a claim that the other transport was physically tested.

The Security Keys list stores one named entry per OpenPGP card serial, with its
supported transports and a checkmark on the selected key. Details show public
keys, fingerprints, and the transport used for registration. Re-registering the
same serial updates its record. You can explicitly select another card or remove
a registration; removing the selected card does not automatically select another.
Only the selected card participates in discovery, and registrations cannot change
during a card session. Public records and the selection are saved atomically.

**Wired (USB or Lightning):** connect the key, then choose **Register wired security key**. Connect
only one smart card recognized by the system. When wired support is enabled, the wired connection takes precedence even for a key registered over NFC;
the card identity must still match. When already connected, private operations proceed without
an extra availability prompt. Otherwise, the app asks you to insert it and continue
or cancel. The actual card and key are checked before sending the PIN.

**NFC:** choose **Register NFC security key** and tap once to read public information;
registration does not require a PIN or change the key. Registered public data can
answer discovery while the card service is enabled. Every private operation asks
whether you want to use the key; there is no persistent readiness switch. Canceling
ends the current operation without requesting a PIN or opening a card connection.

For signing or decryption, HIbiki requests the PIN first, then opens the NFC sheet
and asks you to tap the same key. Keep it near the phone until the operation ends.
The serial number, keygrip and fingerprint must still match the registered record
before the PIN is sent. A different key fails the operation. After changing keys
on a security key, register it again.

NFC discovery describes the registered public snapshot, not proof that a physical
key is currently in range. Live mutable fields such as retry counters are not
invented from cached data. PIN failures report the card's actual returned status.
HIbiki does not automatically retry PIN verification or replay private operations.
The existing requester-side session binding means a failed selected provider ends
that operation; a new operation can discover other available providers.

Supported key families: RSA 2048/3072/4096, Ed25519, X25519, NIST P-256/P-384/P-521.
The key's firmware and configured OpenPGP algorithms determine what it can use.
Password input still follows the desktop agent: it may be supplied by the iPhone,
the requesting computer, or another enabled participant.

## Lifecycle and storage

Only the foreground app receives requests. Backgrounding disconnects the relay,
cancels prompts and native requests, and releases card connections. The temporary
inactive state caused by the NFC sheet does not disconnect. Returning reconnects
without replaying work. There is no APNs integration or claimed background service.

The independently generated identity is stored in a non-synchronizing Keychain
item accessible only while the device is unlocked, on this device only. Public
trust histories, quarantine markers, and card information are atomically written
under protected Application Support and excluded from backups. PINs are neither
persisted nor deliberately logged; Rust secret buffers are cleared on drop.
Swift/system text-input internals can retain copies outside the app's control;
the app clears its UI state promptly and does not claim complete Swift heap erasure.

## Tests

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo build --locked --workspace
python3 tests/integration.py
python3 tests/mobile.py
python3 tests/mobile_tls.py
xcodebuild -project ios/HIbiki.xcodeproj -scheme HIbiki \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro Max' \
  CODE_SIGNING_ALLOWED=NO test
```

`tests/mobile.py` uses the production mobile core against a real relay and GnuPG,
with isolated software APDU responses and temporary test keys. It never opens a
reader or the user's GnuPG home. Public keygrip vectors were independently produced
with libgcrypt. The simulator tests exercise the Swift bridge and onboarding.
`tests/mobile_tls.py` verifies default rejection of a self-signed, wrong-host TLS
certificate, successful connection with explicit bypass, and plaintext connection
without bypass, using only a local test relay.

The GnuPG/APDU tests cover RSA 2048/3072/4096, Ed25519/X25519 and all three
supported NIST curves, plus channel admission, rotation, revocation, cancellation,
wrong-PIN handling and per-operation card confirmation. These are software tests, not
physical wired or NFC acceptance tests. Unsigned simulator builds can show a
Keychain entitlement error during identity creation; use a signed build for
end-to-end app pairing and Keychain validation.

Hardware release checklist (must run on an actual iPhone and YubiKey):

- NFC entitlement and permission handling; wired detection and reader contention.
- Register, learn public keys, sign/verify, encrypt/decrypt using the installed key
  algorithms over both wired and NFC.
- PIN from the phone, computer, and third device; cancellation and competing inputs.
- Touch-required operations, removal, changing the presented key, NFC timeout,
  locked phone, backgrounding, relay disconnection, revocation and channel deletion.
- Respect the key's PIN retry counter. Automated tests intentionally use only
  emulated cards for wrong-PIN and blocked-PIN scenarios.
