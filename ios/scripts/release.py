#!/usr/bin/env python3
"""App Store Connect API authentication and iOS release preflight."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
import unicodedata

import jwt
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

BUNDLE_ID = "com.akinokaede.hibiki"
API = "https://api.appstoreconnect.apple.com/v1"
ROOT = Path(__file__).resolve().parents[2]


def certificate_masks(certificates, team):
    values = {team} if team else set()
    for certificate in certificates:
        for attribute in certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
            common_name = attribute.value
            values.add(common_name)
            match = re.fullmatch(
                r"(?:Apple (?:Development|Distribution)|iPhone (?:Developer|Distribution)|"
                r"Developer ID (?:Application|Installer)): (.+?)(?: \([^()]+\))?", common_name)
            if match:
                values.add(match[1])
        # Apple can also put the account holder's name in the organization field.
        values.update(attribute.value for attribute in
                      certificate.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME))
    return sorted({unicodedata.normalize(form, value)
                   for value in values if value
                   for form in ('NFC', 'NFD')}, key=lambda value: (-len(value), value))


def register_masks(values, output):
    for value in values:
        # Escape workflow-command data, including literal percent signs.
        escaped = value.replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
        output.write(f"::add-mask::{escaped}\n")
    output.flush()


def redact_log(values, source, output):
    for line in source:
        for value in values:
            line = line.replace(value, '***')
        output.write(line)
        output.flush()


def marketing_version(value):
    if not value:
        with (ROOT / "Cargo.toml").open("rb") as source:
            value = tomllib.load(source)["workspace"]["package"]["version"]
    if not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", value):
        raise ValueError("iOS version must be three integers, e.g. 0.1.0 (no prerelease suffix)")
    return value


def next_build(builds, override):
    numbers = []
    for build in builds:
        value = build["attributes"]["version"]
        if not re.fullmatch(r"[1-9][0-9]*", value):
            raise ValueError("Existing ASC build numbers must be integers for automatic numbering")
        numbers.append(int(value))
    latest = max(numbers, default=0)
    if override and not re.fullmatch(r"[1-9][0-9]*", override):
        raise ValueError("iOS build number must be a positive integer")
    number = int(override) if override else latest + 1
    if number <= latest:
        raise ValueError(f"iOS build number must be greater than the existing maximum ({latest})")
    # CFBundleVersion's first component is limited to four digits.
    if number > 9999:
        raise ValueError("Integer build number exceeds 9999; use a new marketing version")
    return str(number)


class AppStoreConnect:
    def __init__(self):
        self.key_id = os.environ["ASC_KEY_ID"]
        self.private_key = Path(os.environ["ASC_KEY_PATH"]).read_text()
        self.app_id = os.environ["ASC_APP_ID"]
        self.issuer_id = os.environ.get("ASC_KEY_ISSUER_ID", "")

    def get(self, url):
        # Pagination links are remote data; never send the JWT to another host.
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https" or parsed.netloc != "api.appstoreconnect.apple.com":
            raise ValueError("Unexpected App Store Connect pagination URL")
        now = int(time.time())
        claims = {"iat": now, "exp": now + 120, "aud": "appstoreconnect-v1"}
        claims.update({"iss": self.issuer_id} if self.issuer_id else {"sub": "user"})
        token = jwt.encode(
            claims,
            self.private_key, algorithm="ES256", headers={"kid": self.key_id, "typ": "JWT"},
        )
        request = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            raise RuntimeError(f"App Store Connect request failed (HTTP {error.code}); check app access and API key permissions") from None

    def builds(self, version):
        query = urllib.parse.urlencode({
            "filter[app]": self.app_id,
            "filter[preReleaseVersion.platform]": "IOS",
            "filter[preReleaseVersion.version]": version,
            "limit": 200,
        })
        url = f"{API}/builds?{query}"
        builds = []
        seen = set()
        while url:
            if url in seen:
                raise ValueError("Repeated App Store Connect pagination URL")
            seen.add(url)
            response = self.get(url)
            builds.extend(response["data"])
            url = response.get("links", {}).get("next")
        return builds

    def check_app(self):
        app = self.get(f"{API}/apps/{urllib.parse.quote(self.app_id, safe='')}")
        if app["data"]["attributes"]["bundleId"] != BUNDLE_ID:
            raise ValueError(f"ASC_APP_ID must identify {BUNDLE_ID}")


def signing_settings(profile, team, identities, now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    expiration = profile["ExpirationDate"].replace(tzinfo=datetime.timezone.utc)
    if expiration <= now:
        raise ValueError("Provisioning profile has expired")
    if team not in profile["TeamIdentifier"]:
        raise ValueError("Provisioning profile does not match APPLE_TEAM_ID")
    entitlements = profile["Entitlements"]
    app_ids = [f"{prefix}.{BUNDLE_ID}" for prefix in profile["ApplicationIdentifierPrefix"]]
    if entitlements.get("application-identifier") not in app_ids:
        raise ValueError(f"Provisioning profile must explicitly match {BUNDLE_ID}")
    if entitlements.get("com.apple.developer.team-identifier") != team:
        raise ValueError("Provisioning profile entitlement has a different team")
    if profile.get("ProvisionedDevices") is not None or profile.get("ProvisionsAllDevices") or entitlements.get("get-task-allow"):
        raise ValueError("An App Store distribution provisioning profile is required")
    with (ROOT / "ios/HIbiki/HIbiki.entitlements").open("rb") as source:
        required = plistlib.load(source)
    for key, value in required.items():
        # The smart-card sandbox entitlement is supplied by the app; Apple's
        # iOS profiles do not list it. NFC is a profile-authorized capability.
        if key == "com.apple.security.smartcard":
            continue
        actual = entitlements.get(key)
        if isinstance(value, list):
            matches = isinstance(actual, list) and set(value).issubset(actual)
        else:
            matches = actual == value
        if not matches:
            raise ValueError(f"Provisioning profile is missing entitlement: {key}")
    fingerprint = next((hashlib.sha1(cert).hexdigest().upper()
                        for cert in profile["DeveloperCertificates"]
                        if hashlib.sha1(cert).hexdigest().upper() in identities), None)
    if not fingerprint:
        raise ValueError("No valid signing identity in the imported P12 matches the provisioning profile")
    uuid = profile["UUID"]
    if not re.fullmatch(r"[0-9a-fA-F-]{36}", uuid):
        raise ValueError("Invalid provisioning profile UUID")
    return {
        "method": "app-store-connect", "destination": "export",
        "teamID": team, "signingStyle": "manual", "signingCertificate": fingerprint,
        "provisioningProfiles": {BUNDLE_ID: uuid},
        "manageAppVersionAndBuildNumber": False, "uploadSymbols": True,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("version")
    masking = commands.add_parser("mask-signing")
    masking.add_argument("p12", type=Path)
    masking.add_argument("output", type=Path)
    redaction = commands.add_parser("redact-log")
    redaction.add_argument("masks", type=Path)
    prepare = commands.add_parser("signing")
    prepare.add_argument("profile", type=Path)
    prepare.add_argument("keychain")
    prepare.add_argument("output", type=Path)
    commands.add_parser("next-build")
    commands.add_parser("wait-build")
    args = parser.parse_args()
    if args.command == "mask-signing":
        try:
            _, certificate, additional = pkcs12.load_key_and_certificates(
                args.p12.read_bytes(), os.environ["APPLE_DISTRIBUTION_P12_PASSWORD"].encode())
        except ValueError:
            raise ValueError("Cannot read signing P12; check the file and its password") from None
        if certificate is None:
            raise ValueError("Signing P12 must contain a certificate and private key")
        values = certificate_masks([certificate, *additional], os.environ["APPLE_TEAM_ID"])
        args.output.write_text(json.dumps(values))
        register_masks(values, sys.stdout)
    elif args.command == "redact-log":
        redact_log(json.loads(args.masks.read_text()), sys.stdin, sys.stdout)
    elif args.command == "version":
        print(marketing_version(os.environ.get("IOS_VERSION", "")))
    elif args.command == "signing":
        with args.profile.open("rb") as source:
            profile = plistlib.load(source)
        identities = subprocess.check_output(
            ["security", "find-identity", "-v", "-p", "codesigning", args.keychain], text=True)
        settings = signing_settings(profile, os.environ["APPLE_TEAM_ID"], identities)
        with args.output.open("wb") as output:
            plistlib.dump(settings, output)
        print(settings["provisioningProfiles"][BUNDLE_ID])
    else:
        client = AppStoreConnect()
        version = marketing_version(os.environ.get("IOS_VERSION", ""))
        if args.command == "next-build":
            client.check_app()
            print(next_build(client.builds(version), os.environ.get("IOS_BUILD_NUMBER", "")))
        else:
            number = os.environ["IOS_BUILD_NUMBER"]
            deadline = time.monotonic() + 600
            while time.monotonic() < deadline:
                for build in client.builds(version):
                    if build["attributes"]["version"] == number:
                        state = build["attributes"]["processingState"]
                        if state in ("FAILED", "INVALID"):
                            raise RuntimeError(f"Apple processing failed: {state}")
                        print(f"App Store Connect received {version} ({number}); processing state: {state}")
                        return
                time.sleep(15)
            raise RuntimeError("Upload was accepted, but the build is not visible after 10 minutes. Check ASC before retrying; it may still appear.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError, KeyError, OSError, jwt.PyJWTError) as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
