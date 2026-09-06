import argparse
from contextlib import redirect_stderr
import io
import json
from pathlib import Path
import tempfile
import unittest
from xml.etree import ElementTree as ET

from android_audit.app_trust import load_policy, parse_signature, report_signers, signer_status
from android_audit.apps import manifest_analysis
from android_audit.core import Context
from android_audit.permission_map import correlate

A, B = 'ab' * 32, 'cd' * 32


class SignerTests(unittest.TestCase):
    def test_cli_blocklist_option_and_prerequisites(self):
        from android_audit.cli import main, parser
        args = parser().parse_args(['scan', '--blocked-certs', 'blocked.json'])
        self.assertEqual(args.blocked_certs, Path('blocked.json'))
        for argv in (['scan', '--approved-certs', 'old.json'],
                     ['scan', '--blocked-certs', 'blocked.json'],
                     ['scan', '--extract-apks', '--modules', 'custom_permissions', '--blocked-certs', 'blocked.json']):
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as result:
                main(['--no-banner', *argv])
            self.assertEqual(result.exception.code, 2)

    def test_only_certificate_digest_and_successful_verification(self):
        text = f'Signer #1 certificate SHA-256 digest: {A}\nSigner #1 public key SHA-256 digest: {B}\nSource Stamp Signer certificate SHA-256 digest: {B}\n'
        self.assertEqual(parse_signature(text)['sha256'], [A])
        self.assertEqual(signer_status(parse_signature(None), [A]), 'not_evaluated')
        self.assertEqual(signer_status(parse_signature('Verified'), [A]), 'not_evaluated')

    def test_any_blocked_signer_matches(self):
        signature = parse_signature(f'Number of signers: 2\nSigner #1 certificate SHA-256 digest: {A}\nSigner #2 certificate SHA-256 digest: {B}\n')
        self.assertEqual(signer_status(signature, [A]), 'blocked')
        self.assertEqual(signer_status(signature, [B]), 'blocked')
        self.assertEqual(signer_status(signature, [A, B]), 'blocked')
        self.assertEqual(signer_status(signature, []), 'no_match')
        self.assertEqual(signer_status(signature, ['ef' * 32]), 'no_match')

    def test_partial_or_malformed_signers_not_evaluated(self):
        for suffix in ('Signer #2 certificate SHA-256 digest: nope\n', ''):
            signature = parse_signature(f'Number of signers: 2\nSigner #1 certificate SHA-256 digest: {A}\n' + suffix)
            self.assertEqual(signer_status(signature, [A]), 'not_evaluated')

    def test_policy_validation_and_normalization(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'policy.json'
            path.write_text(json.dumps({'blocked_sha256': [':'.join(['AB'] * 32)], 'packages': {'test.app': []}}))
            self.assertEqual(load_policy(path), {'blocked_sha256': [A], 'packages': {'test.app': []}})
            for value in ([], {}, {'default': [A]}, {'blocked_sha256': ['bad']}, {'blocked_sha256': [], 'packages': []}, {'blocked_sha256': A}):
                path.write_text(json.dumps(value))
                with self.assertRaises(ValueError):
                    load_policy(path)

    def test_additive_package_blocks_splits_and_report_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            c = Context(argparse.Namespace(serial='d', user=0,
                signer_policy={'blocked_sha256': [A], 'packages': {'test.app': [B]}}), Path(tmp))
            c.start('app_extraction', 'running_applications')
            apps = [{'package': 'test.app', 'apks': [
                {'path': 'base.apk', 'signature': {'status': 'verified', 'sha256': [B]}},
                {'path': 'split.apk', 'signature': {'status': 'verified', 'sha256': [A]}},
                {'path': 'unknown.apk', 'signature': {'status': 'unavailable'}}]},
                {'package': 'other.app', 'apks': [
                    {'path': 'other.apk', 'signature': {'status': 'verified', 'sha256': [B]}}]}]
            report_signers(c, apps)
            rows = json.loads((c.directory / 'signer-policy.json').read_text())
            self.assertEqual([x['status'] for x in rows], ['blocked', 'blocked', 'not_evaluated', 'no_match'])
            self.assertEqual(len(c.result['findings']), 2)
            self.assertEqual(rows[0]['matched_sha256'], [B])
            self.assertEqual(rows[1]['matched_sha256'], [A])
            self.assertTrue(all(f['rule_id'] == 'HW-APP-011' for f in c.result['findings']))
            self.assertTrue((c.directory / 'blocked-certs.json').exists())


class PermissionMapTests(unittest.TestCase):
    def app(self, package, xml):
        manifest = manifest_analysis(ET.fromstring('<manifest xmlns:android="http://schemas.android.com/apk/res/android">' + xml + '</manifest>'))
        manifest['apk'] = package + '.apk'
        return {'package': package, 'manifests': [manifest]}

    def test_cross_app_requests_guards_and_duplicates(self):
        owner = self.app('owner', '<permission android:name="custom.ACCESS" android:protectionLevel="normal"/><application><service android:name="Api" android:exported="true" android:permission="custom.ACCESS"/></application>')
        caller = self.app('caller', '<uses-permission android:name="custom.ACCESS" android:maxSdkVersion="30"/>')
        row = correlate([owner, caller])[0]
        self.assertTrue(row['weak_exported_guards'])
        self.assertEqual(row['requesters'][0]['max_sdk'], '30')
        self.assertEqual(row['declaring_packages'], ['owner'])
        duplicate = self.app('other', '<permission android:name="custom.ACCESS" android:protectionLevel="signature"/>')
        self.assertEqual(correlate([owner, caller, duplicate])[0]['declaration_status'], 'multiple_declarers')

    def test_missing_declaration_and_provider_path_permissions(self):
        app = self.app('provider', '<application><provider android:name="Data" android:exported="true" android:readPermission="custom.READ"><path-permission android:pathPrefix="/secret" android:writePermission="custom.WRITE"/></provider></application>')
        rows = {row['permission']: row for row in correlate([app])}
        self.assertEqual(rows['custom.WRITE']['protected_components'][0]['guard'], 'path[0].writePermission')
        self.assertEqual(rows['custom.READ']['declaration_status'], 'not_observed_in_scope')
        self.assertFalse(rows['custom.READ']['weak_exported_guards'])

    def test_disabled_components_not_flagged_and_split_declarations_not_conflicts(self):
        app = self.app('owner', '<permission android:name="custom.ACCESS"/><application android:enabled="false"><service android:name="Api" android:exported="true" android:permission="custom.ACCESS"/></application>')
        app['manifests'].append(dict(app['manifests'][0], apk='split.apk'))
        row = correlate([app])[0]
        self.assertFalse(row['weak_exported_guards'])
        self.assertEqual(row['declaration_status'], 'observed')
