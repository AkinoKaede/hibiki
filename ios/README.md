# Hibiki for iOS

SwiftUI client for iOS 18 and later. Bundle identifier: `com.akinokaede.hibiki`.

The app uses the same Rust authentication, signed channel histories, Noise sessions,
and Assuan protocol as the desktop client. It provides native password entry and
OpenPGP card access through USB or Lightning connections (CryptoTokenKit) or NFC (Core NFC). It does not
run GnuPG or a background daemon on iOS.

## Build

Requires Xcode with the iOS SDK, Rust 1.96+, Python 3, and the three Apple targets:

```sh
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
./ios/scripts/build-rust.sh Debug
open ios/Hibiki.xcodeproj
```

Select the shared **Hibiki** scheme. The checked-in Xcode project requires no
third-party project generator. Xcode resolves DeviceKit through Swift Package Manager
to supply the default device model name. After adding source files, regenerate it with:

```sh
python3 ios/scripts/generate-project.py
```

`build-rust.sh` generates UniFFI Swift bindings and `HibikiCore.xcframework`; these
are build artifacts and are not committed. Re-run it after Rust changes. Use
`./ios/scripts/build-rust.sh Release` before an Archive/Release build. Both Debug and Release accept `ws://` and `wss://` servers. TLS certificate
validation is enabled by default.

Choose your own development team in Xcode to run on a physical device, or create
the git-ignored `ios/Local.xcconfig` with `DEVELOPMENT_TEAM = YOUR_TEAM_ID`.
The project includes this optional file for both Debug and Release, including test
targets, and preserves it when regenerating the project. Enable
NFC Tag Reading for the matching App ID and provisioning profile. The app declares
`com.apple.security.smartcard`, NFC `TAG` access, and OpenPGP application ID
`D27600012401`. No signing team or credentials are committed to this repository.

Unsigned verification:

```sh
xcodebuild -project ios/Hibiki.xcodeproj -scheme Hibiki \
  -destination 'generic/platform=iOS Simulator' CODE_SIGNING_ALLOWED=NO build
xcodebuild -project ios/Hibiki.xcodeproj -scheme Hibiki \
  -destination 'generic/platform=iOS' CODE_SIGNING_ALLOWED=NO build
```

## App Store Connect upload

The existing **build** workflow offers three manual build choices: **all**
(the default), **desktop**, and **ios**. The iOS job imports signing credentials,
archives with Xcode, exports an App Store IPA, and uploads with `altool` using
an App Store Connect API key.
Pushes and pull requests do not trigger an iOS upload.

### One-time setup

Create an App Store Connect app with bundle ID `com.akinokaede.hibiki`, and enable
NFC Tag Reading for its explicit Apple Developer App ID. Generate an **App Store
distribution** provisioning profile that permits the app's NFC `TAG` entitlement.
The smart-card sandbox entitlement remains in the app and is not listed in Apple
iOS provisioning profiles. Export the matching Apple Distribution certificate
**with its private key** as a `.p12` file. Development, Ad Hoc,
and enterprise profiles are not accepted.

Use a team API key with its Issuer ID, or a personal API key without an Issuer
ID. Its role must permit access to this app and uploading builds (Developer,
App Manager, or Admin as applicable). Add the following under the
repository's **Settings → Secrets and variables → Actions**:

| Kind | Name | Value |
| --- | --- | --- |
| Secret | `ASC_KEY` | Base64-encoded `.p8` key |
| Secret | `ASC_KEY_ID` | API key ID |
| Secret | `ASC_KEY_ISSUER_ID` | Issuer ID for a team key; omit for a personal key |
| Secret | `APPLE_DISTRIBUTION_CERTIFICATES_P12` | Base64-encoded distribution certificate and private key |
| Secret | `APPLE_DISTRIBUTION_P12_PASSWORD` | P12 export password; an empty password is supported |
| Secret | `APPLE_PROVISIONING_PROFILE` | Base64-encoded App Store `.mobileprovision` file |
| Variable | `APPLE_TEAM_ID` | Apple Developer team ID |
| Variable | `ASC_APP_ID` | Numeric Apple ID from the app's App Information page |

On macOS, encode a credential with `base64 -i /path/to/file | pbcopy`, then paste
it directly into the corresponding GitHub secret. Keep these files out of Git.
The workflow creates a random temporary Keychain password and removes the
Keychain, installed profile, and private files when the release script exits.
Use GitHub-hosted runners for this workflow.
Before importing the P12, the job registers the certificate's account-holder name,
certificate common name, organization, and Team ID with GitHub Actions `add-mask`.
Saved text logs are also redacted before artifact upload. The signed IPA retains
its required signing metadata.

### Run a build

1. Open **Actions → build → Run workflow** and select the source branch or tag.
2. Leave `build` as **all** to build desktop packages and upload iOS, or choose
   **ios** to upload iOS alone.
3. Set the required `version` input to a three-component numeric version such as
   `0.1.0`, without `v`. It controls the iOS marketing version, Rust binary
   versions, and package filenames. Desktop releases automatically use Git tag
   `v0.1.0`; iOS-only runs do not create a tag. The input must match the committed
   Cargo workspace version and lockfile. Developers must manually bump and commit
   both before releasing. Prerelease suffixes are not accepted; the
   desktop `prereleased` checkbox marks the GitHub Release and does not affect iOS.
4. Normally leave `ios_build_number` empty: the job queries every ASC build for
   that iOS marketing version and uses the highest integer plus one, starting
   at 1. An override must be a larger integer, at most 9999. Upload jobs are
   serialized across branches; avoid concurrent uploads from other tools.

The job uses macOS 15 with Xcode 26.3, builds the Release Rust XCFramework, resolves
locked Swift packages, and applies the workflow version through Xcode build
settings. Release signing uses app-specific `HIBIKI_*` overrides so Swift package
resource bundles do not receive the app's provisioning profile.
The selected app, profile, signing identity, expiry, team, and
entitlements are checked before compilation.

The job saves the IPA, dSYM archive, and available logs as an
`ios-RUN_ID-ATTEMPT` Actions artifact for 14 days, including logs on failure.
After upload, it waits up to ten minutes for the build to appear in ASC and
reports its processing state. Successful upload does not mean Apple processing
or review has finished. TestFlight group distribution and App Store review are
managed manually; the workflow does not cancel or modify existing submissions.

If Apple accepts an upload but visibility times out, inspect ASC before rerunning.
If the build number has been consumed but is not returned by the API yet, wait
or supply a larger number. For signing errors, regenerate the profile after
enabling the required capabilities and ensure the P12 contains its matching
private key. For HTTP 401/403 or upload authentication errors, verify that the
Issuer ID matches the team key (or is unset for a personal key), and that the
key can access and upload to this app.

The app leaves the export-compliance declaration unset. Complete the encryption
questionnaire in App Store Connect after uploading and supply any required
documentation before distributing the build.
Use the hardware release checklist below before distributing a build.

Release tooling checks (Python 3.11+):

```sh
python3 -m venv /tmp/hibiki-release-venv
/tmp/hibiki-release-venv/bin/pip install -r ios/scripts/release-requirements.txt
/tmp/hibiki-release-venv/bin/python -m unittest discover -s ios/scripts -p test_release.py
shellcheck ios/scripts/release.sh
actionlint .github/workflows/build.yml
```

## Pairing

1. Enter your server address in **Server URL**; the field starts empty. Without
   a scheme, the app probes `wss://` first and then `ws://` if WSS fails. Each
   candidate must complete Hibiki protocol validation and device authentication.
   An explicit `wss://` or `ws://` uses only that protocol. Ports, custom paths and
   queries are preserved; an omitted path (or `/`) becomes `/hibiki`.
   **Hostname** defaults to the model reported by DeviceKit (for example,
   `iPhone 16 Pro`). You can edit it; saved names are preserved. Use the same
   server as your computers. Under **Advanced**, **Skip TLS Certificate
   Validation** disables certificate trust, hostname and validity checks for TLS
   when explicitly enabled. It is off by default and does not affect plaintext
   connections. **Get started** saves only a successfully authenticated server
   URL, including the detected protocol. Each probe has a 15-second limit (up to
   30 seconds for both protocols); failed setup keeps the address editable.
2. Create a channel, or paste a `hibiki-v1:` / `hibiki-init-v1:` invitation and
   enter the separately shared PSK.
3. For member invitations, compare **all 24 public-key words and the request ID**
   on an existing member before approving. The words are public identity data,
   not a recovery phrase. Pending requests remain until approved or invalidated; they have no time limit.
4. Enable Password Entry and/or OpenPGP Card. Both start disabled. On the
   requesting computer, configure the Hibiki adapters as described in the
   [desktop usage guide](../USAGE.md#4-connect-the-requesting-devices-agent).
   The app can approve members, share invitations, rotate PSKs, revoke
   identities, and leave channels.

To switch servers, open **Settings → Connection → Disconnect from server** and
confirm. This works offline, stops current requests, clears local pairing and the
device identity, and returns to setup with an empty address field. Security key registrations and the device
name are kept; password/card services and the TLS bypass are reset to off. Connect
to the new server and pair again. Returning to the old server also requires pairing
with a new device identity. This local disconnect does not delete server-side
channels or revoke the old membership; remaining members can remove the old device.
An interrupted reset is completed before setup or restore can reuse any state.

## Security Keys

The OpenPGP application must already contain your keys. Import its public OpenPGP
certificate on the requesting computer. The app does not create or import private
keys, change PINs, reset the key, or expose remote raw APDU commands.

The registration form shows only the other transport's support switch: **NFC
support** when reading over a USB connection, or **USB connection support** when reading over NFC. It is
on by default; turn it off for keys without that interface. This is a declared
capability, not a claim that the other transport was physically tested.

The Security Keys list stores one named entry per OpenPGP card serial, with its
supported transports and a checkmark on the selected key. Details show public
keys, fingerprints, and the transport used for registration. Re-registering the
same serial updates its record. You can explicitly select another card or remove
a registration; removing the selected card does not automatically select another.
Only the selected card participates in discovery, and registrations cannot change
during a card session. Public records and the selection are saved atomically.

**USB (including Lightning):** connect the key, then open the **+** menu in Security Keys
and choose **Register USB security key**. Connect
only one smart card recognized by the system. When USB support is enabled, the USB connection takes precedence even for a key registered over NFC;
the card identity must still match. If USB is initially absent, you can insert the
key while confirming the request or entering its PIN. The app checks USB again
when you submit and chooses the connection after receiving the PIN. For keys
supporting both interfaces, USB takes precedence if now connected; otherwise,
tap the key using NFC. This also applies to keys originally registered over USB.
The app never switches interfaces after a card operation fails.
When already connected, private operations proceed without
an extra availability prompt. Otherwise, the app asks you to insert it and continue
or cancel. The actual card and key are checked before sending the PIN.

**NFC:** open the **+** menu and choose **Register NFC security key** and tap once to read public information;
registration does not require a PIN or change the key. Registered public data can
answer discovery while the card service is enabled. Every private operation asks
whether you want to use the key; there is no persistent readiness switch. Canceling
ends the current operation without requesting a PIN or opening a card connection.

For signing or decryption, Hibiki requests the PIN first, then opens the NFC sheet
and asks you to tap the same key. Keep it near the phone until the operation ends.
The serial number, keygrip and fingerprint must still match the registered record
before the PIN is sent. A different key fails the operation. After changing keys
on a security key, register it again.

NFC discovery describes the registered public snapshot, not proof that a physical
key is currently in range. Live mutable fields such as retry counters are not
invented from cached data. PIN failures report the card's actual returned status.
Hibiki does not automatically retry PIN verification or replay private operations.
A waiting request can reach the app when it returns online before the caller's
original deadline. Card operations remain bound to the original device and card;
unstarted commands may resume after selection and data preparation are restored.
A command with an unknown execution result is never automatically repeated.

Supported key families: RSA 2048/3072/4096, Ed25519, X25519, NIST P-256/P-384/P-521.
The key's firmware and configured OpenPGP algorithms determine what it can use.
Password input still follows the desktop agent: it may be supplied by the iPhone,
the requesting computer, or another enabled participant.
The iPhone form collects the password once, with an X to cancel and an in-form
Continue button to submit. Any confirmation required when setting a new passphrase
remains the requesting agent's responsibility; Hibiki does not report `PIN_REPEATED`.

## Lifecycle and storage

Only the foreground app receives requests. Backgrounding disconnects the server,
cancels prompts and native requests, and releases card connections. The temporary
inactive state caused by the NFC sheet does not disconnect. Returning reconnects
and accepts still-pending requests. Completed, canceled, expired, and previously
executed requests are not replayed. There is no APNs integration or claimed background service.

The independently generated identity is stored in a non-synchronizing Keychain
item accessible only while the device is unlocked, on this device only. Public
trust histories, quarantine markers, and card information are atomically written
under protected Application Support and excluded from backups. PINs are neither
persisted nor deliberately logged; Rust secret buffers are cleared on drop.
Swift/system text-input internals can retain copies outside the app's control;
the app clears its UI state promptly and does not claim complete Swift heap erasure.

## Tests

Check Chinese localization spacing (requires `jq`):

```sh
./ios/scripts/check-zh-localization.sh
```

The check follows Termind's Chinese spacing rules for existing `zh-Hans` and
`zh-Hant` translations, including plural variations: no spaces between Chinese
and English, digits, or format placeholders; no spaces around punctuation; and
Chinese text uses Chinese punctuation. It also runs in CI.

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo build --locked --workspace
python3 tests/integration.py
python3 tests/mobile.py
python3 tests/mobile_tls.py
xcodebuild -project ios/Hibiki.xcodeproj -scheme Hibiki \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro Max' \
  CODE_SIGNING_ALLOWED=YES CODE_SIGN_IDENTITY=- DEVELOPMENT_TEAM= test
```

`tests/mobile.py` uses the production mobile core against a real server and GnuPG,
with isolated software APDU responses and temporary test keys. It never opens a
reader or the user's GnuPG home. Public keygrip vectors were independently produced
with libgcrypt. The simulator tests exercise the Swift bridge and onboarding.
`tests/mobile_tls.py` verifies default rejection of a self-signed, wrong-host TLS
certificate, successful connection with explicit bypass, and plaintext connection
without bypass, using only a local test server.

The GnuPG/APDU tests cover RSA 2048/3072/4096, Ed25519/X25519 and all three
supported NIST curves, plus channel admission, rotation, revocation, cancellation,
wrong-PIN handling and per-operation card confirmation. These are software tests, not
physical USB or NFC acceptance tests. Unsigned simulator builds can show a
Keychain entitlement error during identity creation; use a signed build for
end-to-end app pairing and Keychain validation.

Hardware release checklist (must run on an actual iPhone and YubiKey):

- NFC entitlement and permission handling; USB detection and reader contention.
- Register, learn public keys, sign/verify, encrypt/decrypt using the installed key
  algorithms over both USB and NFC.
- PIN from the phone, computer, and third device; cancellation and competing inputs.
- Touch-required operations, removal, changing the presented key, NFC timeout,
  locked phone, backgrounding, server disconnection, revocation and channel deletion.
- Respect the key's PIN retry counter. Automated tests intentionally use only
  emulated cards for wrong-PIN and blocked-PIN scenarios.

## Server policy and pending requests

The app uses protocol `hibiki/1`; the server and clients must use matching builds.
The Channels screen shows Create only when the connected server permits client channel
creation. Otherwise, obtain an initialization invitation from the administrator.

A joining device can withdraw its pending request from Status or Join channel.
The pending request ID is saved locally so this remains available after reopening
the app. Approval, rejection, withdrawal or PSK rotation ends the waiting state.
An active member can reject a request from its verification screen; rejection
removes only that request and permits a later new application.
