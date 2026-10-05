# Repository Guidelines

## Project Structure & Module Organization

Hibiki forwards OpenPGP card access and PIN entry between devices. The Rust workspace contains `lib/` (protocol, cryptography, Assuan, and `proto/` schemas), `core/` (shared transport and sessions), `client/` (CLI, TUI, daemon, and GPG adapters), `server/` (WebSocket routing and SQLite storage), and `mobile/` (UniFFI mobile core). `ios/` holds the SwiftUI app, assets, and XCTest suites. Rust integration tests live in `lib/tests/`; Python system tests live in `tests/`. Configuration examples are in `examples/`, deployment files in `packaging/`, and release tooling in `scripts/`.

## Build, Test, and Development Commands

Use Rust 1.96+, Python 3, and Git; desktop integration tests also require GnuPG 2.4 or 2.5.

- `cargo build --locked --workspace --all-targets`: build binaries and test targets.
- `cargo build --locked --release --workspace`: build optimized release binaries.
- `cargo fmt --all -- --check`: check Rust formatting.
- `cargo clippy --locked --workspace --all-targets -- -D warnings`: enforce warning-free lint checks.
- `cargo test --locked --workspace`: run Rust tests.
- `python3 tests/integration.py`: exercise GnuPG and multi-device workflows after building.
- `cargo run -p hibiki-server -- --config examples/server.toml`: start a local server.

For iOS, run `./ios/scripts/build-rust.sh Debug`, then open `ios/Hibiki.xcodeproj`. See `ios/README.md` for simulator testing.

## Coding Style & Naming Conventions

Use rustfmt defaults and four-space indentation in Rust and Swift. Use `snake_case` for Rust modules/functions and `PascalCase` for types; Swift uses `lowerCamelCase` members. Follow surrounding Python style. Keep protocol definitions in `lib/proto/`. Do not commit generated UniFFI bindings or XCFrameworks. Regenerate the Xcode project with `python3 ios/scripts/generate-project.py` after adding iOS sources.

## Testing Guidelines

Use Rust unit/integration tests, Python system scripts, and XCTest. Name tests for the behavior they verify; follow existing `test_*` Python and `*Tests.swift` conventions. No numeric coverage threshold is configured. Run relevant system suites (`server.py`, `mobile.py`, `mobile_tls.py`, `pairing.py`, `tui.py`) for affected behavior. Hardware changes also need real-card validation; respect PIN retry limits.

## Commit & Pull Request Guidelines

History mixes imperative subjects with prefixes such as `feat(ios):`, `fix(ios):`, and `docs:`. Write concise, scoped subjects. PRs should explain behavior changes, link relevant issues, list validation commands/results, and include screenshots for UI changes. Update usage, architecture, or protocol documentation when corresponding behavior changes.
