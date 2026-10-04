#!/bin/bash
# Called by the optional iOS job in build.yml on an ephemeral macOS runner.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
: "${RUNNER_TEMP:?Run this script on a GitHub Actions macOS runner}"
for name in ASC_KEY ASC_KEY_ID ASC_APP_ID APPLE_TEAM_ID APPLE_DISTRIBUTION_CERTIFICATES_P12 APPLE_PROVISIONING_PROFILE; do
    if [[ -z "${!name:-}" ]]; then
        echo "error: Missing required release setting: $name" >&2
        exit 1
    fi
done
# An empty P12 password is valid, but the variable must be supplied.
: "${APPLE_DISTRIBUTION_P12_PASSWORD?Missing P12 password variable}"
if [[ ! "$ASC_KEY_ID" =~ ^[A-Za-z0-9]+$ ]]; then
    echo 'error: Invalid ASC_KEY_ID' >&2
    exit 1
fi
export IOS_VERSION
IOS_VERSION="$(python3 ios/scripts/release.py version)"
OUTPUT="$ROOT/ios/build-release"
mkdir -p "$OUTPUT"
PRIVATE_DIR="$(mktemp -d "$RUNNER_TEMP/hibiki-signing.XXXXXX")"
KEYCHAIN_PATH="$PRIVATE_DIR/distribution.keychain-db"
PROFILE_PATH=''
# Preserve the runner's search list; do not change its default keychain.
security list-keychains -d user > "$PRIVATE_DIR/previous-keychains.txt"
cleanup() {
    set +e
    if [[ -n "$PROFILE_PATH" ]]; then rm -f "$PROFILE_PATH"; fi
    python3 - "$PRIVATE_DIR/previous-keychains.txt" <<'PY'
import pathlib, shlex, subprocess, sys
subprocess.run(['security', 'list-keychains', '-d', 'user', '-s',
                *shlex.split(pathlib.Path(sys.argv[1]).read_text())], check=False)
PY
    security delete-keychain "$KEYCHAIN_PATH" >/dev/null 2>&1 || true
    rm -rf "$PRIVATE_DIR"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
umask 077
export API_PRIVATE_KEYS_DIR="$PRIVATE_DIR/private_keys"
mkdir -p "$API_PRIVATE_KEYS_DIR"
# altool selects individual/team authentication by the key filename prefix.
KEY_PREFIX=ApiKey
if [[ -n "${ASC_KEY_ISSUER_ID:-}" ]]; then KEY_PREFIX=AuthKey; fi
export ASC_KEY_PATH="$API_PRIVATE_KEYS_DIR/${KEY_PREFIX}_$ASC_KEY_ID.p8"
printf '%s' "$ASC_KEY" | base64 --decode > "$ASC_KEY_PATH"
printf '%s' "$APPLE_DISTRIBUTION_CERTIFICATES_P12" | base64 --decode > "$PRIVATE_DIR/distribution.p12"
printf '%s' "$APPLE_PROVISIONING_PROFILE" | base64 --decode > "$PRIVATE_DIR/profile.mobileprovision"
unset ASC_KEY APPLE_DISTRIBUTION_CERTIFICATES_P12 APPLE_PROVISIONING_PROFILE
# Register names before security/Xcode can print them. Keep artifact logs redacted too:
# GitHub's add-mask only covers the Actions console, not uploaded files.
python3 ios/scripts/release.py mask-signing "$PRIVATE_DIR/distribution.p12" "$PRIVATE_DIR/masks.json"
release_log() {
    python3 ios/scripts/release.py redact-log "$PRIVATE_DIR/masks.json" | tee "$OUTPUT/$1.log"
}
KEYCHAIN_PASSWORD="$(openssl rand -hex 32)"
security create-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH"
security set-keychain-settings -lut 21600 "$KEYCHAIN_PATH"
security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH"
security import "$PRIVATE_DIR/distribution.p12" -P "$APPLE_DISTRIBUTION_P12_PASSWORD" -t cert -f pkcs12 -k "$KEYCHAIN_PATH" -T /usr/bin/codesign -T /usr/bin/security
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH" >/dev/null
python3 - "$PRIVATE_DIR/previous-keychains.txt" "$KEYCHAIN_PATH" <<'PY'
import pathlib, shlex, subprocess, sys
subprocess.run(['security', 'list-keychains', '-d', 'user', '-s', sys.argv[2],
                *shlex.split(pathlib.Path(sys.argv[1]).read_text())], check=True)
PY
security cms -D -i "$PRIVATE_DIR/profile.mobileprovision" > "$PRIVATE_DIR/profile.plist"
PROFILE_UUID="$(python3 ios/scripts/release.py signing "$PRIVATE_DIR/profile.plist" "$KEYCHAIN_PATH" "$PRIVATE_DIR/ExportOptions.plist")"
PROFILE_DIR="$HOME/Library/Developer/Xcode/UserData/Provisioning Profiles"
mkdir -p "$PROFILE_DIR"
# Do not overwrite a pre-existing profile if the script is run on a reused runner.
if [[ -e "$PROFILE_DIR/$PROFILE_UUID.mobileprovision" ]]; then
    echo 'error: Provisioning profile already exists on runner; use a clean runner' >&2
    exit 1
fi
PROFILE_PATH="$PROFILE_DIR/$PROFILE_UUID.mobileprovision"
cp "$PRIVATE_DIR/profile.mobileprovision" "$PROFILE_PATH"
SIGNING_CERTIFICATE="$(/usr/libexec/PlistBuddy -c 'Print :signingCertificate' "$PRIVATE_DIR/ExportOptions.plist")"
export IOS_BUILD_NUMBER
IOS_BUILD_NUMBER="$(python3 ios/scripts/release.py next-build)"
printf 'Building iOS %s (%s)\n' "$IOS_VERSION" "$IOS_BUILD_NUMBER"

./ios/scripts/build-rust.sh Release 2>&1 | release_log rust
XCODE_ARGS=(
    -project ios/Hibiki.xcodeproj -scheme Hibiki
    -clonedSourcePackagesDirPath "$RUNNER_TEMP/hibiki-source-packages"
)
xcodebuild "${XCODE_ARGS[@]}" -resolvePackageDependencies -onlyUsePackageVersionsFromResolvedFile 2>&1 | release_log packages
xcodebuild "${XCODE_ARGS[@]}" archive \
    -disableAutomaticPackageResolution -onlyUsePackageVersionsFromResolvedFile \
    -configuration Release -destination 'generic/platform=iOS' \
    -derivedDataPath "$RUNNER_TEMP/hibiki-derived-data" \
    -archivePath "$OUTPUT/Hibiki.xcarchive" \
    "MARKETING_VERSION=$IOS_VERSION" "CURRENT_PROJECT_VERSION=$IOS_BUILD_NUMBER" \
    "DEVELOPMENT_TEAM=$APPLE_TEAM_ID" HIBIKI_CODE_SIGN_STYLE=Manual \
    "HIBIKI_CODE_SIGN_IDENTITY=$SIGNING_CERTIFICATE" "HIBIKI_PROVISIONING_PROFILE_SPECIFIER=$PROFILE_UUID" \
    2>&1 | release_log archive
(cd "$OUTPUT/Hibiki.xcarchive" && /usr/bin/zip -qr "$OUTPUT/Hibiki.dSYMs.zip" dSYMs)
xcodebuild -exportArchive -archivePath "$OUTPUT/Hibiki.xcarchive" \
    -exportPath "$OUTPUT/export" -exportOptionsPlist "$PRIVATE_DIR/ExportOptions.plist" \
    2>&1 | release_log export
shopt -s nullglob
IPAS=("$OUTPUT/export/"*.ipa)
if [[ ${#IPAS[@]} -ne 1 ]]; then
    echo 'error: Expected exactly one exported IPA' >&2
    exit 1
fi
# Personal keys require a placeholder issuer; team keys use their real issuer.
xcrun altool --upload-app -f "${IPAS[0]}" -t ios \
    --api-key "$ASC_KEY_ID" --api-issuer "${ASC_KEY_ISSUER_ID:-00000000-0000-0000-0000-000000000000}" \
    2>&1 | release_log upload
# Wait for visibility so a following serialized run can see the consumed number.
python3 ios/scripts/release.py wait-build 2>&1 | release_log asc
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    printf '### iOS upload\n\nUploaded **%s (%s)** to App Store Connect.\n\n' "$IOS_VERSION" "$IOS_BUILD_NUMBER" >> "$GITHUB_STEP_SUMMARY"
    cat "$OUTPUT/asc.log" >> "$GITHUB_STEP_SUMMARY"
fi
