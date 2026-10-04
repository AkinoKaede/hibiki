# HIbiki

Use an OpenPGP Card on another device and enter its PIN on any participating device. HIbiki forwards **scdaemon and pinentry over Assuan stdio**, while your native `gpg`, `gpg-agent`, and Git signing workflow stay on the requesting machine.

For example, laptop A can sign a commit using a card attached to desktop B, with the PIN entered on device C. A's agent receives the PIN and passes it to B's selected card session. Multiple devices can offer input at once; the first successful response wins and the other prompts close.

Each device independently chooses whether to provide card access, password entry, both, or neither. Both services are **disabled by default**. Remote traffic is encrypted end to end through a WebSocket relay.

## iOS app

The SwiftUI app in [`ios/`](ios/README.md) supports iOS 18+, with bundle ID
`com.akinokaede.hibiki`. It provides native password entry and OpenPGP security key
access through wired and NFC, using the same Rust protocol and trust core
as the desktop client. It also manages channel pairing and membership.

The app is online while open. Services start disabled. NFC registration saves
only public card information. Each private operation asks for confirmation unless
a wired card is already connected (its identity is verified before using the PIN). PIN entry precedes the NFC
tap used for signing/decryption. Canceling ends the current operation.
See the [iOS build, setup, and hardware verification guide](ios/README.md).

## Requirements and build

- macOS or Linux
- Rust 1.96 or later
- GnuPG 2.4 or 2.5
- Native scdaemon on devices providing card access; native Pinentry on devices providing input

```sh
cargo build --locked --release --workspace
export PATH="$PWD/target/release:$PATH"
```

| Program | Purpose |
| --- | --- |
| `hibiki` | Device setup, channel management, and the local daemon |
| `hibiki-server` | Authentication, channel membership, and encrypted traffic relay |
| `hibiki-scdaemon` | Stdio adapter used by the requesting device's agent |
| `hibiki-pinentry` | Stdio adapter used by the requesting device's agent |

## Packages and releases

GitHub Actions builds separate `hibiki-VERSION-TARGET.tar.gz` and
`hibiki-server-VERSION-TARGET.tar.gz` archives for Linux (x86_64/ARM64) and
macOS (Intel/Apple Silicon). The client archive includes all three desktop
binaries and, on Linux, a user systemd unit. Both archives contain the relevant
example configuration and this guide. Linux binaries are built on Ubuntu 24.04
and require glibc 2.39 or later; macOS binaries are built on macOS 15.
GnuPG and native Pinentry/scdaemon remain host dependencies for clients.

Download archives from GitHub Releases, verify them with
`sha256sum --check --ignore-missing SHA256SUMS` on Linux (or
`shasum -a 256 --check --ignore-missing SHA256SUMS` on macOS), then extract the
archive for your platform. From the extracted client directory:

```sh
install -d "$HOME/.local/bin"
install -m 755 bin/hibiki bin/hibiki-scdaemon bin/hibiki-pinentry "$HOME/.local/bin/"
export PATH="$HOME/.local/bin:$PATH"
```

For a standalone relay, install `bin/hibiki-server` from the server archive to
your preferred executable directory and follow the relay setup below.

To build the same archives locally (Python 3.11+ and Rust required):

```sh
python3 scripts/package.py
# Optional: --target x86_64-unknown-linux-gnu --output dist
```

Cross-compilation requires installing the Rust target and its linker/toolchain;
CI uses native runners for each platform. Archives and individual SHA-256 files
are written to `dist/`.

There are three GitHub Actions workflows:

- **test** runs Rust checks and GnuPG integration tests on Linux and macOS on
  pushes, pull requests and manual dispatches. iOS CI is currently disabled.
- **build** builds all four binary targets on pushes and pull requests, and
  uploads the archives as Actions artifacts. To prepare a release, start it from
  Actions → build → Run workflow, select the source branch/tag, enter a `tag`
  matching `[workspace.package].version` (for example `v0.1.0`), and set the
  `prereleased` checkbox. Manual runs also create a **draft** GitHub Release with
  the archives and `SHA256SUMS`. An existing tag must point to the selected
  commit; no existing release or tag is overwritten. Use a new version/tag for
  a new draft. No Docker image is built at this stage.
- **docker** runs only after you publish the draft Release (or promote a
  prerelease to a full release). It smoke-tests the container and publishes a
  multi-platform `linux/amd64,linux/arm64` image to
  `ghcr.io/OWNER/REPOSITORY/hibiki-server` (owner/repository are lowercase).
  Every image receives a version tag. Full releases update both `latest` and
  `prereleased`; prereleases update only `prereleased`.

Check the independent test workflow, draft files and prerelease setting, then click
Publish release when ready. The repository must permit the workflows'
`GITHUB_TOKEN` to write releases and GHCR packages. GHCR package visibility is
managed separately from repository visibility.

### Docker relay

Build and start a relay from the repository root:

```sh
docker compose -f server/compose.yml up -d --build
curl --fail http://127.0.0.1:7749/healthz
```

The Compose service binds only the host loopback address. Put a TLS reverse
proxy in front of it for remote access, forwarding `/hibiki` WebSocket upgrades.
The image listens on `0.0.0.0:7749` internally, runs as UID/GID `10001`, and stores
SQLite in a named volume at `/var/lib/hibiki`. A bind-mounted data directory must
instead be owned by `10001:10001` with mode `0700` (database files use `0600`).
Do not remove the data volume when upgrading.

To run a published image:

```sh
docker run -d --name hibiki-server --restart unless-stopped \
  -p 127.0.0.1:7749:7749 \
  -v hibiki-server-data:/var/lib/hibiki \
  ghcr.io/OWNER/REPOSITORY/hibiki-server:0.1.0
```

Mount a customized copy of `server/container.toml` read-only at
`/etc/hibiki/server.toml` to change relay policy. Preserve the container listen
address and persistent database path unless intentionally changing the deployment.
CLI flags override environment variables, which override the TOML configuration:

| Environment variable | CLI flag | Purpose |
| --- | --- | --- |
| `HIBIKI_SERVER_CONFIG` | `--config` | Configuration file path |
| `HIBIKI_SERVER_LISTEN` | `--listen` | Listen address, e.g. `0.0.0.0:7749` |
| `HIBIKI_SERVER_DATABASE` | `--database` | SQLite path |
| `HIBIKI_SERVER_ALLOW_CLIENT_CHANNEL_CREATION` | `--allow-client-channel-creation` | `true` or `false` |

For example, add `-e HIBIKI_SERVER_ALLOW_CLIENT_CHANNEL_CREATION=false` to
`docker run` to reserve channel creation for the administrator. The image sets
`HIBIKI_SERVER_CONFIG=/etc/hibiki/server.toml` and `RUST_LOG=info` by default.
If changing the listen port, also change the published port and set the image's
`HIBIKI_SERVER_HEALTHCHECK_URL` to the corresponding local `/healthz` URL.
The relay handles SIGTERM and SIGINT for graceful shutdown.

Administrator commands can run against the same database:

```sh
docker exec -it hibiki-server hibiki-server --config /etc/hibiki/server.toml channel list
# For Compose:
docker compose -f server/compose.yml exec server \
  hibiki-server --config /etc/hibiki/server.toml channel list
```

### Linux user service

Initialize and pair your device using the setup below before starting the service.
After installing the client binaries into `~/.local/bin`, run these commands from
the extracted Linux client archive:

```sh
install -d "$HOME/.config/systemd/user"
install -m 644 systemd/hibiki.service "$HOME/.config/systemd/user/hibiki.service"
systemctl --user daemon-reload
systemctl --user enable --now hibiki.service
journalctl --user -u hibiki.service -f
```

When installing from source, use `packaging/systemd/hibiki.service` instead.
The unit runs `~/.local/bin/hibiki daemon` under your own user account with the
usual XDG configuration and identity. Use `systemctl --user edit hibiki.service`
to override `ExecStart` (clear it first with an empty `ExecStart=`) or set
`Environment=XDG_CONFIG_HOME=...` / `Environment=XDG_DATA_HOME=...` if needed.
Management commands and GPG adapters must use the same paths.
Restart with `systemctl --user restart hibiki.service` after configuration changes.

For GUI Pinentry, import the active desktop session's environment before starting
or restarting the service:

```sh
systemctl --user import-environment DISPLAY WAYLAND_DISPLAY XAUTHORITY DBUS_SESSION_BUS_ADDRESS
systemctl --user restart hibiki.service
```

Use a native GUI Pinentry for a background service. Terminal Pinentry requires a
valid local `GPG_TTY` and `TERM` in the service environment. To keep a headless
client running after logout, an administrator can enable lingering with
`sudo loginctl enable-linger "$USER"`; GUI input still requires a desktop session.
Do not also run `hibiki daemon` manually while the service is active.

## Setup

### 1. Run a relay

Copy the [server configuration](examples/server.toml) into a private directory, then start the server:

```sh
mkdir -m 700 deploy
cp examples/server.toml deploy/server.toml
hibiki-server --config deploy/server.toml
```

The server runs in the foreground and listens on `127.0.0.1:7749` by default. It serves WebSocket traffic at `/hibiki` and a health endpoint at `/healthz`. For remote use, expose it through a TLS endpoint and use a `wss://` URL. Channel admission relies on TLS to protect the pre-shared key (PSK).

The example stores its database at `deploy/data/hibiki.sqlite3`. If `database` is omitted, the default is `$XDG_DATA_HOME/hibiki/server/hibiki.sqlite3`, or `~/.local/share/hibiki/server/hibiki.sqlite3` when XDG is unset. Relative database paths resolve against the configuration file's directory.

The following steps use `wss://hibiki.example.com/hibiki`; replace it with your relay URL. For local development, use `ws://127.0.0.1:7749/hibiki` and add `--allow-insecure` to each `hibiki init` command.

### 2. Pair devices in a channel

On the first device:

```sh
hibiki init --server wss://hibiki.example.com/hibiki --name laptop
hibiki channel create personal
hibiki channel invite personal
```

Keep the PSK printed by `create`. Share the invitation and PSK separately through trusted channels.

On each additional device:

```sh
hibiki init --server wss://hibiki.example.com/hibiki --name desktop
hibiki channel join 'hibiki-v1:...'
```

`join` prompts for the PSK and waits for approval. In another terminal on an existing member device, run:

```sh
hibiki channel approve personal
```

Compare the joining device's 24 public-key verification words before answering `y`. Approval defaults to No, and pending requests expire after 10 minutes. Any existing member can approve a device. Initialize each device separately; do not copy another device's identity file.

### 3. Enable the services each device will provide

Edit `~/.config/hibiki/client.toml`, or the corresponding XDG path. See the complete [client configuration](examples/client.toml).

```toml
[scdaemon]
enabled = true
# program = "/usr/lib/gnupg/scdaemon"

[pinentry]
enabled = true
# program = "/opt/homebrew/bin/pinentry-mac"
```

These switches control whether the device accepts requests and participates as a provider. They do not restrict its ability to request services from other devices.

| Device role | `scdaemon.enabled` | `pinentry.enabled` |
| --- | --- | --- |
| Request services only | `false` | `false` |
| Provide a card | `true` | `false` |
| Offer password input | `false` | `true` |
| Provide both | `true` | `true` |

When `program` is omitted, HIbiki locates the native program using `gpgconf --list-components`. A native program path must not point to a HIbiki adapter.

Pinentry uses the providing device's display environment. Choose a GUI Pinentry available on that device, or set its local `GPG_TTY` and `TERM` in the daemon's environment for terminal input. Requesting devices cannot supply remote display, TTY, owner, or filesystem settings.

Run the daemon on every participating device:

```sh
hibiki daemon
```

The daemon runs in the foreground. Restart it after changing service configuration. Providing a service does not require changes to that device's `gpg-agent.conf`.

### 4. Connect the requesting device's agent

Choose the channel on each requesting device:

```sh
hibiki use personal
```

Joining a channel does not select it automatically. Each new adapter session keeps the channel selection it started with.

Add either or both lines to the requesting device's `gpg-agent.conf`, using the absolute paths of your built binaries:

```text
scdaemon-program /absolute/path/hibiki-scdaemon
pinentry-program /absolute/path/hibiki-pinentry
```

Use only the pinentry line for remote password entry with local keys. Use only the scdaemon line for remote card access with your existing local Pinentry. Use both to allow a third device to enter the card PIN.

Restart the agent for the GnuPG home you configured, including after changing the default channel for an existing card session:

```sh
gpgconf --homedir /your/gnupg/home --kill gpg-agent
```

The next GPG operation starts the agent again. For a custom HIbiki configuration, set `HIBIKI_CONFIG` before starting the agent so the adapters inherit it. Management commands also accept `--config PATH`.

## Sign and decrypt

Import the card's public key on the requesting device, then let the agent learn the card:

```sh
gpg --import public.asc
gpg --card-status
```

Continue using native GPG:

```sh
printf 'hello\n' > message.txt
gpg --local-user YOUR_FINGERPRINT --armor --detach-sign message.txt
gpg --verify message.txt.asc message.txt

gpg --trust-model always --recipient YOUR_FINGERPRINT --encrypt message.txt
gpg --decrypt message.txt.gpg
```

For Git signing, run these commands in your repository:

```sh
git config gpg.program "$(command -v gpg)"
git config user.signingkey YOUR_FINGERPRINT
git config commit.gpgsign true
git commit -S -m 'Signed with HIbiki'
```

## Session behavior and limits

**Card access.** HIbiki discovers enabled providers in parallel and selects the first OpenPGP Card matching the requested serial number or keygrip. Without a target, it selects the first available card. Once selected, card state, data, PIN inquiries, signing, and decryption stay on that backend until an explicit reset or card selection. A failure does not switch cards or replay a private operation.

Each device grants one exclusive scdaemon session at a time; busy devices reject additional sessions. HIbiki starts its own native scdaemon with `--server` in `$XDG_DATA_HOME/hibiki/scdaemon`. Reader settings can go in that directory's `scdaemon.conf`. It does not connect to existing agent/scdaemon sockets or terminate other services holding a reader.

**Password entry.** Each `GETPIN`, `CONFIRM`, or `MESSAGE` request starts a fresh race among enabled local and remote providers. The first complete successful response wins. A canceled or failed window only eliminates that candidate; remaining candidates can still succeed. Losing processes are closed, and their partial input is discarded.

The native agent or card validates the password. A retry starts a new race; HIbiki never tries the losing candidates' passwords. Answers go only to the requester. Multiple Pinentry inquiries are serialized upstream, with each answer routed back to its original candidate.

**Transport and lifecycle.** Both agent-to-adapter and HIbiki-to-native-program connections use stdio. The adapters reach the local daemon through a private Unix socket. Assuan inquiries preserve their parameters, binary data, percent escapes, and native error codes.

- No extra scdaemon socket is exposed. `GETINFO socket_name` returns no data, and additional concurrent card connections from the same agent are unsupported.
- Card discovery, public-key reading, signing, and decryption are supported. PIN changes, key writing, key generation, and raw APDU commands are rejected on both ends.
- Each active command has a 120-second default timeout, configurable from 1 to 3600 seconds. Idle time does not consume the next command's deadline.
- Caller exit, timeout, disconnect, revocation, or channel deletion closes affected sessions and owned backends. Reconnection enables new requests without replaying unfinished operations.
- The daemon currently needs a relay connection even when only local providers are used.

## Channel administration

```sh
hibiki channel list
hibiki device list
hibiki channel pending personal
hibiki channel rotate-psk personal
hibiki channel revoke personal DEVICE_ID
hibiki channel leave personal
```

PSKs control admission. The relay stores Argon2id verifiers; rotating a PSK invalidates pending requests but preserves approved membership. Use `--psk-file` for automation. A revoked identity cannot rejoin the same channel; a device that voluntarily leaves can request admission again.

To reserve channel creation for the server administrator, set `allow_client_channel_creation = false` in the server configuration:

```sh
hibiki-server --config deploy/server.toml channel create personal --server wss://hibiki.example.com/hibiki
hibiki-server --config deploy/server.toml channel list
hibiki-server --config deploy/server.toml channel delete personal
```

Server-side creation prints a single-use `hibiki-init-v1:...` invitation and a PSK. The first device claims it with `hibiki channel join`; later devices use ordinary invitations. A running relay checks for administrator deletions every second and closes affected sessions. Recreating a channel name produces a new channel ID.

## Trust and storage

Devices authenticate with Ed25519 identities and establish `Noise_XX_25519_ChaChaPoly_BLAKE2s` sessions bound to the protocol, channel, device identities, and session ID. Signed membership histories and saved checkpoints detect rollback, identity substitution, and conflicting histories. Service discovery is encrypted too.

The relay can see membership, routing, timing, and ciphertext sizes, but cannot read Assuan traffic. It does not queue operations for offline devices. Approved channel members can use enabled services and approve additional members.

Card private keys stay on the card; software private keys stay on the requesting device. PINs and passphrases pass through the input device and requester, and card PINs also reach the selected card provider. HIbiki clears secret buffers after use, does not cache passwords or enable Pinentry's external password cache, and keeps protocol bodies and secrets out of logs. Native agent caching still applies.

| Data | Location |
| --- | --- |
| Configuration | `$XDG_CONFIG_HOME/hibiki` (default `~/.config/hibiki`) |
| Identity and trust | `$XDG_DATA_HOME/hibiki` (default `~/.local/share/hibiki`) |
| Local IPC | `$XDG_RUNTIME_DIR/hibiki`, or a private per-user temporary directory |

Private files use mode `0600` and directories use `0700`. Back up identity and trust records together.

The protocol identifier remains **`hibiki/1`** and the WebSocket path is **`/hibiki`**. This stdio implementation is incompatible with the previous agent proxy despite retaining that identifier. Update every device and initialize fresh identities and pairing. Old configuration and invitations are not loaded or migrated; historical files outside the workspace are left untouched.

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
```

CI runs on Ubuntu 24.04 and macOS. Integration tests use temporary identities and GnuPG homes, controlled stdio Pinentry processes, and an OpenPGP Card emulator. Real GnuPG exercises card learning, RSA signing and decryption, Git signing, password races and retries, cancellation, revocation, disconnects, and process cleanup.

Emulation does not replace hardware testing. Validate PIN retries, touch requirements, card removal, reader contention, and interrupted operations on real test cards on each target platform, respecting the card's PIN retry limit.
