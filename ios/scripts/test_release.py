import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
import unicodedata
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
import jwt

import release


class ReleaseTests(unittest.TestCase):
    def test_signing_names_masked_before_logging(self):
        key = ec.generate_private_key(ec.SECP256R1())
        person = 'Test José Example'
        team = 'TEAM123456'
        common_name = f'Apple Distribution: {person} ({team})'
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, person),
        ])
        certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                       .public_key(key.public_key()).serial_number(1)
                       .not_valid_before(datetime.datetime(2026, 1, 1))
                       .not_valid_after(datetime.datetime(2030, 1, 1)).sign(key, hashes.SHA256()))
        data = pkcs12.serialize_key_and_certificates(
            b'test', key, certificate, None, serialization.BestAvailableEncryption(b'password'))
        with tempfile.TemporaryDirectory() as directory:
            p12 = Path(directory) / 'test.p12'
            masks = Path(directory) / 'masks.json'
            p12.write_bytes(data)
            output = io.StringIO()
            with patch.dict(os.environ, {'APPLE_TEAM_ID': team, 'APPLE_DISTRIBUTION_P12_PASSWORD': 'password'}), \
                    patch('sys.argv', ['release.py', 'mask-signing', str(p12), str(masks)]), \
                    patch('sys.stdout', output):
                release.main()
            values = json.loads(masks.read_text())
            self.assertIn(person, values)
            self.assertIn(common_name, values)
            self.assertIn(team, values)
            self.assertIn(f'::add-mask::{person}\n', output.getvalue())
            raw_log = f'Signing Identity: "{common_name}"\nOwner: {unicodedata.normalize("NFD", person)}\nTeam: {team}\nARCHIVE SUCCEEDED\n'
            artifact_log = io.StringIO()
            release.redact_log(values, io.StringIO(raw_log), artifact_log)
            self.assertEqual(artifact_log.getvalue(), 'Signing Identity: "***"\nOwner: ***\nTeam: ***\nARCHIVE SUCCEEDED\n')

    def test_mask_command_escaping(self):
        output = io.StringIO()
        release.register_masks(['Name%with\r\ncharacters'], output)
        self.assertEqual(output.getvalue(), '::add-mask::Name%25with%0D%0Acharacters\n')

    def test_name_extraction_without_organization(self):
        certificate = unittest.mock.Mock()
        for prefix in ('Apple Distribution', 'Apple Development', 'Developer ID Application'):
            certificate.subject = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, f'{prefix}: Test Person (TEAM123456)')])
            with self.subTest(prefix=prefix):
                self.assertIn('Test Person', release.certificate_masks([certificate], 'TEAM123456'))

    def test_version(self):
        self.assertEqual(release.marketing_version('1.2.3'), '1.2.3')
        self.assertRegex(release.marketing_version(''), r'^\d+\.\d+\.\d+$')
        for version in ('v1.2.3', '1.2.3-beta.1', '1.2', '01.2.3', '1.2.3\n'):
            with self.subTest(version=version), self.assertRaises(ValueError):
                release.marketing_version(version)

    def test_numbering(self):
        builds = [{'attributes': {'version': value}} for value in ('1', '8', '3')]
        self.assertEqual(release.next_build([], ''), '1')
        self.assertEqual(release.next_build(builds, ''), '9')
        self.assertEqual(release.next_build(builds, '12'), '12')
        for value in ('8', '2', '0', '1.2', '009', '10000'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                release.next_build(builds, value)
        with self.assertRaises(ValueError):
            release.next_build([{'attributes': {'version': '9999'}}], '')

    def test_pagination_and_filters(self):
        client = object.__new__(release.AppStoreConnect)
        client.app_id = '123'
        page2 = release.API + '/builds?cursor=next'
        with patch.object(client, 'get', side_effect=[
            {'data': [{'attributes': {'version': '3'}}], 'links': {'next': page2}},
            {'data': [{'attributes': {'version': '12'}}], 'links': {}},
        ]) as get:
            self.assertEqual(release.next_build(client.builds('1.2.3'), ''), '13')
        query = release.urllib.parse.parse_qs(release.urllib.parse.urlsplit(get.call_args_list[0].args[0]).query)
        self.assertEqual(query['filter[app]'], ['123'])
        self.assertEqual(query['filter[preReleaseVersion.version]'], ['1.2.3'])
        self.assertEqual(query['filter[preReleaseVersion.platform]'], ['IOS'])

    def test_personal_key_authentication(self):
        private_key = ec.generate_private_key(ec.SECP256R1())
        pem = private_key.private_bytes(serialization.Encoding.PEM,
                                       serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption())
        with tempfile.TemporaryDirectory() as directory:
            key_path = Path(directory) / 'ApiKey_TEST.p8'
            key_path.write_bytes(pem)
            with patch.dict(os.environ, {'ASC_KEY_ID': 'TEST', 'ASC_KEY_PATH': str(key_path), 'ASC_APP_ID': '123', 'ASC_KEY_ISSUER_ID': ''}):
                client = release.AppStoreConnect()
            with patch.object(release.urllib.request, 'urlopen', side_effect=release.urllib.error.HTTPError(
                    release.API, 403, 'Forbidden', {}, None)) as urlopen:
                with self.assertRaisesRegex(RuntimeError, 'HTTP 403'):
                    client.get(release.API + '/apps/123')
            request = urlopen.call_args.args[0]
            token = request.get_header('Authorization').removeprefix('Bearer ')
            claims = jwt.decode(token, private_key.public_key(), algorithms=['ES256'], audience='appstoreconnect-v1')
            self.assertEqual(claims['sub'], 'user')
            self.assertNotIn('iss', claims)
            self.assertEqual(jwt.get_unverified_header(token)['kid'], 'TEST')
            client.issuer_id = '16eea6fe-3201-432c-873f-57a85550b4c0'
            with patch.object(release.urllib.request, 'urlopen', side_effect=release.urllib.error.HTTPError(
                    release.API, 403, 'Forbidden', {}, None)) as urlopen:
                with self.assertRaises(RuntimeError):
                    client.get(release.API + '/apps/123')
            token = urlopen.call_args.args[0].get_header('Authorization').removeprefix('Bearer ')
            claims = jwt.decode(token, private_key.public_key(), algorithms=['ES256'], audience='appstoreconnect-v1')
            self.assertEqual(claims['iss'], client.issuer_id)
            self.assertNotIn('sub', claims)
            with self.assertRaisesRegex(ValueError, 'pagination URL'):
                client.get('https://example.org/builds')

    def test_wrong_app(self):
        client = object.__new__(release.AppStoreConnect)
        client.app_id = '123'
        with patch.object(client, 'get', return_value={'data': {'attributes': {'bundleId': 'other.app'}}}):
            with self.assertRaisesRegex(ValueError, 'ASC_APP_ID'):
                client.check_app()

    def test_failed_apple_processing(self):
        with patch.object(release, 'AppStoreConnect') as client, \
                patch.dict(os.environ, {'IOS_VERSION': '1.2.3', 'IOS_BUILD_NUMBER': '7'}), \
                patch('sys.argv', ['release.py', 'wait-build']):
            client.return_value.builds.return_value = [
                {'attributes': {'version': '7', 'processingState': 'INVALID'}}]
            with self.assertRaisesRegex(RuntimeError, 'Apple processing failed'):
                release.main()

    def test_upload_visibility_timeout(self):
        with patch.object(release, 'AppStoreConnect') as client, \
                patch.dict(os.environ, {'IOS_VERSION': '1.2.3', 'IOS_BUILD_NUMBER': '7'}), \
                patch('sys.argv', ['release.py', 'wait-build']), \
                patch.object(release.time, 'monotonic', side_effect=[0, 1, 601]), \
                patch.object(release.time, 'sleep'):
            client.return_value.builds.return_value = []
            with self.assertRaisesRegex(RuntimeError, 'Check ASC before retrying'):
                release.main()

    def profile(self):
        return {
            'UUID': '12345678-1234-1234-1234-123456789ABC',
            'ExpirationDate': datetime.datetime(2030, 1, 1),
            'TeamIdentifier': ['TEAM123456'],
            'ApplicationIdentifierPrefix': ['PREFIX1234'],
            'DeveloperCertificates': [b'test certificate'],
            'Entitlements': {
                'application-identifier': 'PREFIX1234.' + release.BUNDLE_ID,
                'com.apple.developer.team-identifier': 'TEAM123456',
                'com.apple.security.smartcard': True,
                'com.apple.developer.nfc.readersession.formats': ['TAG'],
                'get-task-allow': False,
            },
        }

    def settings(self, profile, identities=None):
        if identities is None:
            identities = hashlib.sha1(b'test certificate').hexdigest().upper()
        return release.signing_settings(profile, 'TEAM123456', identities,
                                        datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc))

    def test_distribution_profile(self):
        profile = self.profile()
        del profile['Entitlements']['com.apple.security.smartcard']
        settings = self.settings(profile)
        self.assertEqual(settings['method'], 'app-store-connect')
        self.assertFalse(settings['manageAppVersionAndBuildNumber'])
        self.assertEqual(settings['provisioningProfiles'][release.BUNDLE_ID], self.profile()['UUID'])

    def test_invalid_profile(self):
        mutations = [
            ('ExpirationDate', datetime.datetime(2020, 1, 1)),
            ('TeamIdentifier', ['OTHERTEAM']),
            ('ProvisionedDevices', []),
            ('ProvisionsAllDevices', True),
        ]
        for key, value in mutations:
            profile = self.profile()
            profile[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.settings(profile)
        for key, value in [('get-task-allow', True),
                           ('application-identifier', 'PREFIX1234.*'),
                           ('com.apple.developer.nfc.readersession.formats', ['NDEF'])]:
            profile = self.profile()
            profile['Entitlements'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.settings(profile)
        with self.assertRaisesRegex(ValueError, 'signing identity'):
            self.settings(self.profile(), identities='')


if __name__ == '__main__':
    unittest.main()
