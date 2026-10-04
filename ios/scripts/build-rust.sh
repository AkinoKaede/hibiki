#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
export PATH="$HOME/.cargo/bin:$PATH"
CONFIG="${1:-Debug}"
PROFILE=debug
CARGO_PROFILE=dev
if [[ "$CONFIG" == Release ]]; then PROFILE=release; CARGO_PROFILE=release; fi
export IPHONEOS_DEPLOYMENT_TARGET=18.0
mkdir -p ios/Generated ios/Frameworks target/ios-headers target/ios-simulator
# The host library supplies UniFFI metadata. The host executable generates Swift bindings.
cargo build --locked -p hibiki-mobile --lib --profile "$CARGO_PROFILE"
cargo run --locked -p hibiki-mobile --features bindgen --bin hibiki-bindgen -- generate --library "target/$PROFILE/libhibiki_mobile.dylib" --language swift --out-dir ios/Generated
cp ios/Generated/hibiki_mobileFFI.h target/ios-headers/
cp ios/Generated/hibiki_mobileFFI.modulemap target/ios-headers/module.modulemap
for RUST_TARGET in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios; do
    cargo build --locked -p hibiki-mobile --lib --target "$RUST_TARGET" --profile "$CARGO_PROFILE"
done
xcrun lipo -create "target/aarch64-apple-ios-sim/$PROFILE/libhibiki_mobile.a" "target/x86_64-apple-ios/$PROFILE/libhibiki_mobile.a" -output target/ios-simulator/libhibiki_mobile.a
# Only generated build artifacts are replaced.
rm -rf ios/Frameworks/HibikiCore.xcframework
xcodebuild -create-xcframework -library "$ROOT/target/aarch64-apple-ios/$PROFILE/libhibiki_mobile.a" -headers "$ROOT/target/ios-headers" -library "$ROOT/target/ios-simulator/libhibiki_mobile.a" -headers "$ROOT/target/ios-headers" -output "$ROOT/ios/Frameworks/HibikiCore.xcframework"
printf '%s\n' "$CONFIG" > ios/Frameworks/configuration.txt
