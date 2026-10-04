# Hibiki usage guide

[Overview](README.md) · [Architecture](ARCHITECTURE.md) · [iOS guide](ios/README.md)

This guide covers desktop installation, relay deployment, device pairing, GPG
integration, and channel administration. For native iPhone setup and card access,
see the [iOS guide](ios/README.md).

## Contents

- [Requirements and build](#requirements-and-build)
- [Install release packages](#install-release-packages)
- [Setup](#setup)
- [Sign and decrypt](#sign-and-decrypt)
- [Diagnose setup and connection issues](#diagnose-setup-and-connection-issues)
- [Channel administration](#channel-administration)
- [Docker relay](#docker-relay)
- [Linux user service](#linux-user-service)
- [Build and publish releases](#build-and-publish-releases)

## Requirements and build

Desktop clients require:

- macOS or Linux
- GnuPG 2.4 or 2.5
- Native scdaemon on devices providing card access; native Pinentry on devices providing input

Building from source also requires Rust 1.96 or later. A relay-only host does not
need GnuPG, scdaemon, or Pinentry. From the repository root:

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

`hibiki` highlights status, warnings, errors, and pairing details in color when
writing to a terminal. Redirected output stays plain text. Set `NO_COLOR=1` to
disable colors or `CLICOLOR_FORCE=1` to force them.

## Install release packages

GitHub Actions builds separate `hibiki-VERSION-TARGET.tar.xz` and
`hibiki-server-VERSION-TARGET.tar.xz` archives for Linux (x86_64/ARM64) and
macOS (Intel/Apple Silicon). Linux offers both `*-unknown-linux-gnu` (glibc)
and `*-unknown-linux-musl` (static) binaries for each architecture.
The client archive includes all three desktop
binaries and, on Linux, a user systemd unit. Both archives contain the relevant
example configuration, README, usage guide, and architecture guide.
GNU Linux binaries are built on Ubuntu
24.04 and require glibc 2.39 or later; musl binaries have no dynamic libc
requirement. macOS binaries are built on macOS 15.
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
your preferred executable directory and follow [relay setup](#1-run-a-relay).

To build the same archives locally (Python 3.11+ and Rust required):

```sh
python3 scripts/package.py
# Optional: --target x86_64-unknown-linux-gnu --output dist
```

Cross-compilation requires installing the Rust target and its linker/toolchain;
CI uses native runners for each architecture. For a musl build on Linux, install
`musl-tools` and the matching Rust musl target, and set its linker to `musl-gcc`
(as in [build.yml](.github/workflows/build.yml)). Archives and individual SHA-256
files are written to `dist/`.

## Setup

### 1. Run a relay

Install the [server configuration](examples/server.toml) and prepare the system data directory for the account that will run the relay. These commands use your current account:

```sh
sudo install -d -m 0755 /etc/hibiki
sudo install -m 0644 examples/server.toml /etc/hibiki/server.toml
sudo install -d -m 0700 -o "$(id -un)" -g "$(id -gn)" /var/lib/hibiki
hibiki-server
```

The server runs in the foreground and listens on `127.0.0.1:7749` by default. It serves WebSocket traffic at `/hibiki` and a health endpoint at `/healthz`. For remote use, expose it through a TLS endpoint and use a `wss://` URL. Channel admission relies on TLS to protect the pre-shared key (PSK).

The relay searches for configuration in this order:

1. An explicit `--config` or `HIBIKI_SERVER_CONFIG` path (CLI takes precedence).
2. `/etc/hibiki/server.toml`.
3. `/usr/local/etc/hibiki/server.toml` for local installations.

It loads the first existing file without merging configurations, or uses built-in defaults if neither default file exists. An explicitly selected missing file, or an unreadable or invalid configuration, is an error; it does not fall through to another configuration. CLI flags override environment variables, which override the configuration. The server does not require `HOME` or search client XDG directories.

The database defaults to `/var/lib/hibiki/hibiki.sqlite3` regardless of which configuration file is selected. For a local-prefix deployment, install the configuration at `/usr/local/etc/hibiki/server.toml` and explicitly set `database = "/usr/local/var/lib/hibiki/hibiki.sqlite3"` if the data should also live under `/usr/local`. Prepare that data directory for the relay's account using the same ownership and mode as above.

For a dedicated service account, assign the data directory to that account instead; the directory must have mode `0700` and database files use `0600`. Administrator commands use the same configuration search order as the relay.

For an unprivileged local deployment, copy the example into `deploy/server.toml`, change `database` to `"data/hibiki.sqlite3"`, and run `hibiki-server --config deploy/server.toml`. Use the same `--config` for administrator commands. Relative database overrides resolve against the configuration file's directory, or the current working directory if no configuration is loaded. Missing data directories are created with mode `0700`.

The following steps use `wss://hibiki.example.com/hibiki`; replace it with your relay URL. For local development, use `ws://127.0.0.1:7749/hibiki` and add `--allow-insecure` to each `hibiki init` command.

### 2. Pair devices in a channel

Channel creation is reserved for the server administrator by default. On the relay host, create a channel (the relay can keep running):

```sh
hibiki-server channel create personal --server wss://hibiki.example.com/hibiki
```

Keep the printed PSK and single-use `hibiki-init-v1:...` invitation. Share them separately through trusted channels with the first device's owner. For Docker, run the same command with `docker exec` and `--config /etc/hibiki/server.toml` as described in [Docker relay](#docker-relay).

On the first device (`--name` is optional and defaults to the system hostname), claim the channel and produce a member invitation:

```sh
hibiki init --server wss://hibiki.example.com/hibiki --name laptop
hibiki channel join 'hibiki-init-v1:...'
hibiki channel invite personal
```

`join` prompts for the administrator-provided PSK; this first claim does not need member approval. Share the new `hibiki-v1:...` member invitation and PSK separately through trusted channels. If the administrator explicitly sets `allow_client_channel_creation = true`, the first device can instead run `hibiki channel create personal` followed by `hibiki channel invite personal`.

On each additional device:

```sh
hibiki init --server wss://hibiki.example.com/hibiki --name desktop
hibiki channel join 'hibiki-v1:...'
```

`join` prompts for the PSK and waits for approval. In another terminal on an existing member device, run:

```sh
hibiki channel approve personal
```

Compare the joining device's request ID and all 24 public-key verification words before answering `y`. Approval defaults to No. Pending requests remain until approved, rejected by a member, withdrawn by the applicant, invalidated by PSK rotation, or removed with the channel. A waiting `join` exits when its request is removed. Ctrl-C only stops waiting; use `hibiki channel leave NAME` to cancel joining. Any existing member can approve a device. Initialize each device separately; do not copy another device's identity file.

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

When `program` is omitted, Hibiki locates the native program using `gpgconf --list-components`. Both services support this automatic discovery; `gpgconf` must be in the daemon's `PATH`, or set `gpgconf_program` to its absolute path. Run `gpgconf --list-components` to inspect the selected binaries. Discovery uses GnuPG's reported component paths and does not automatically choose a GUI Pinentry such as `pinentry-mac`. Set `[pinentry].program` explicitly when needed. A native program path must not point to a Hibiki adapter.

Pinentry uses the providing device's display environment. Choose a GUI Pinentry available on that device, or set its local `GPG_TTY` and `TERM` in the daemon's environment for terminal input. Requesting devices cannot supply remote display, TTY, owner, or filesystem settings.

Run the daemon on every participating device:

```sh
hibiki daemon
```

The daemon runs in the foreground. Before connecting, it verifies that every enabled native provider resolves to an executable; a missing or invalid program stops startup with an actionable error. This check does not open a reader or display a PIN dialog. Restart it after changing service configuration. Providing a service does not require changes to that device's `gpg-agent.conf`.

### 4. Connect the requesting device's agent

Choose the channel on each requesting device:

```sh
hibiki use personal
```

Joining a channel does not select it automatically. Each new adapter session keeps the channel selection it started with.

Add either or both lines to the requesting device's `gpg-agent.conf`, using the absolute paths of your installed or built binaries:

```text
scdaemon-program /absolute/path/hibiki-scdaemon
pinentry-program /absolute/path/hibiki-pinentry
```

Use only the pinentry line for remote password entry with local keys. Use only the scdaemon line for remote card access with your existing local Pinentry. Use both to allow a third device to enter the card PIN.

Restart the agent for the GnuPG home you configured, including after changing the default channel for an existing card session:

```sh
gpgconf --homedir /your/gnupg/home --kill gpg-agent
```

The next GPG operation starts the agent again. For a custom Hibiki configuration, set `HIBIKI_CONFIG` before starting the agent so the adapters inherit it. Management commands also accept `--config PATH`.

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
git commit -S -m 'Signed with Hibiki'
```

See [session behavior and limits](ARCHITECTURE.md#session-behavior-and-limits)
for card selection, competing PIN prompts, timeouts, and interrupted operations.

## Diagnose setup and connection issues

`hibiki init` prints the next setup steps. Run `hibiki setup` at any time to see the
configuration path, channel-selection instructions, GPG adapter paths and
background-service guidance again. These commands do not modify GnuPG configuration.

```sh
hibiki status
hibiki doctor
```

`status` queries the live local daemon even before its first relay connection. It
shows relay connectivity, active provider switches, the selected channel and
configuration changes that require a restart. `doctor` additionally checks enabled
native executables and authenticates with the relay to report channel-creation
policy. Both exit nonzero when a checked component needs attention. Native checks
do not test physical card access or GUI/TTY availability. For custom configuration,
CLI commands and adapters both honor `HIBIKI_CONFIG`; CLI `--config` takes precedence.

Local adapter startup waits at most `operation_timeout_seconds` (default 120)
for the first relay connection, then returns an Assuan error suggesting `hibiki status`.
Each waiting connection runs independently, so it does not block status queries or
other callers. Once connected, existing operation/reconnection deadlines apply.

## Channel administration

```sh
hibiki channel list
hibiki device list
hibiki channel pending personal
hibiki channel reject personal REQUEST_ID
hibiki channel rotate-psk personal
hibiki channel revoke personal DEVICE_ID
hibiki channel leave personal
```

Any active member can reject one pending request; only its applicant can withdraw it. Rejection removes that request and does not permanently ban the device. A new admission still requires the PSK and member approval. Approval and removal are atomic: a removed request cannot subsequently be approved.

`hibiki channel leave NAME` withdraws all of this device's pending requests for the channel and leaves if it is already a member, including if approval happened just before cancellation. No request ID is needed. It also clears the default channel when applicable; repeating it after leaving is harmless.

PSKs control admission. The relay stores Argon2id verifiers; rotating a PSK invalidates pending requests but preserves approved membership. Use `--psk-file` for automation. A revoked identity cannot rejoin the same channel; a device that voluntarily leaves can request admission again.

Channel creation is reserved for the server administrator by default (`allow_client_channel_creation = false`):

```sh
hibiki-server channel create personal --server wss://hibiki.example.com/hibiki
hibiki-server channel list
hibiki-server channel delete personal
```

Server-side creation prints a single-use `hibiki-init-v1:...` invitation and a PSK. The first device claims it with `hibiki channel join`; later devices use ordinary invitations. A running relay checks for administrator deletions every second and closes affected sessions. Recreating a channel name produces a new channel ID.

## Docker relay

Build and start a relay from the repository root:

```sh
docker compose -f server/compose.yml up -d --build
docker compose -f server/compose.yml exec server hibiki-server health
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
  ghcr.io/akinokaede/hibiki-server:0.1.0
```

Mount a customized copy of `server/server.toml` read-only at
`/etc/hibiki/server.toml` to change relay policy. Preserve the container listen
address and persistent database path unless intentionally changing the deployment.
CLI flags override environment variables, which override the TOML configuration:

| Environment variable | CLI flag | Purpose |
| --- | --- | --- |
| `HIBIKI_SERVER_CONFIG` | `--config` | Configuration file path |
| `HIBIKI_SERVER_LISTEN` | `--listen` | Listen address, e.g. `0.0.0.0:7749` |
| `HIBIKI_SERVER_DATABASE` | `--database` | SQLite path |
| `HIBIKI_SERVER_ALLOW_CLIENT_CHANNEL_CREATION` | `--allow-client-channel-creation` | `true` or `false` |

Channel creation is reserved for the administrator by default. Add
`-e HIBIKI_SERVER_ALLOW_CLIENT_CHANNEL_CREATION=true` to `docker run` only if
authenticated clients should be able to create channels. The image sets
`HIBIKI_SERVER_CONFIG=/etc/hibiki/server.toml` and `RUST_LOG=info` by default.
Both the image and Compose use `hibiki-server health` for health checks. It probes
`/healthz` at the configured listen address, using loopback for wildcard addresses,
and exits 0 for an HTTP success response or 1 for failure (including a 2-second
timeout). It does not open or create the database. CLI and environment listen
overrides also apply to the probe. If changing the listen port, also change the
published port; the health check follows the configuration automatically.
The relay handles SIGTERM and SIGINT for graceful shutdown.

Administrator commands can run against the same database:

```sh
docker exec -it hibiki-server hibiki-server --config /etc/hibiki/server.toml channel list
# For Compose:
docker compose -f server/compose.yml exec server \
  hibiki-server --config /etc/hibiki/server.toml channel list
```

## Linux user service

Initialize and pair your device using the [setup steps](#setup) before starting the service.
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

## Build and publish releases

There are three GitHub Actions workflows:

- **test** runs Rust checks and GnuPG integration tests on both amd64 (x86_64)
  and arm64 (aarch64), on Linux and macOS, for pushes, pull requests and manual
  dispatches. iOS simulator tests are not currently run in CI.
- **build** builds all six binary targets on relevant source/packaging pushes
  and pull requests, and
  uploads the archives as Actions artifacts. To prepare a release, start it from
  Actions → build → Run workflow, select the source branch/tag, enter a `version`
  without a `v` prefix (for example `0.1.0`), and set the
  `prereleased` checkbox. Manual runs also create a **draft** GitHub Release with
  the archives and `SHA256SUMS`. The Git tag is automatically `vVERSION`; desktop
  binary/package versions and the iOS version follow the input. Versions are
  applied only in the CI checkout, including its Cargo lockfile. An existing tag must point to the selected
  commit; no existing release or tag is overwritten. Use a new version/tag for
  a new draft. The `build` selector defaults to **all**, which also signs and uploads
  the iOS app to App Store Connect. Choose **desktop** for desktop packages only,
  or **ios** for an iOS upload without a draft Release (`prereleased`
  is ignored for **ios**). iOS uploads require the Apple credentials described
  in the [iOS release guide](ios/README.md#app-store-connect-upload).
  Push and pull request builds continue to build desktop packages only.
  No Docker image is built at this stage.
- **docker** runs only after you publish the draft Release (or promote a
  prerelease to a full release). It smoke-tests the container on native amd64 and arm64 Linux runners and publishes a
  multi-platform `linux/amd64,linux/arm64` image to
  `ghcr.io/akinokaede/hibiki-server`.
  Every image receives a version tag. Full releases update both `latest` and
  `prereleased`; prereleases update only `prereleased`.

Check the independent test workflow, draft files and prerelease setting, then click
Publish release when ready. The repository must permit the workflows'
`GITHUB_TOKEN` to write releases and GHCR packages. GHCR package visibility is
managed separately from repository visibility.
