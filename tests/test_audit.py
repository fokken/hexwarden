import argparse
from datetime import date
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from android_audit.apps import manifest_analysis
from android_audit.cli import main
from android_audit.core import Context, execute
from android_audit.modules.logging_secrets import detect
from android_audit.modules.outdated_os import patch_age
from android_audit.modules import registry
from android_audit.modules.network import wildcard_listeners


class ManifestTests(unittest.TestCase):
    def manifest(self, body, target=35, attributes=''):
        return manifest_analysis(ET.fromstring(f'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="test.app"><uses-sdk android:targetSdkVersion="{target}"/><application {attributes}>{body}</application></manifest>'))

    def test_inherited_permission(self):
        result = self.manifest('<service android:name=".S" android:exported="true"/>', attributes='android:permission="test.PRIVATE"')
        self.assertFalse(result['components'][0]['candidate_unguarded'])

    def test_provider_defaults(self):
        self.assertTrue(self.manifest('<provider android:name=".P"/>', 16)['components'][0]['exported'])
        self.assertFalse(self.manifest('<provider android:name=".P"/>', 17)['components'][0]['exported'])

    def test_provider_asymmetric_permissions(self):
        result = self.manifest('<provider android:name=".P" android:exported="true" android:readPermission="test.READ"/>')
        self.assertTrue(result['components'][0]['candidate_unguarded'])

    def test_disabled_component(self):
        result = self.manifest('<receiver android:name=".R" android:exported="true" android:enabled="false"/>')
        self.assertFalse(result['components'][0]['candidate_unguarded'])

    def test_alias_inheritance(self):
        result = self.manifest('<activity android:name=".A" android:permission="test.SECRET"/><activity-alias android:name=".Alias" android:targetActivity=".A" android:exported="true"/>')
        self.assertFalse(result['components'][1]['candidate_unguarded'])

    def test_unknown_resource_export(self):
        result = self.manifest('<service android:name=".S" android:exported="@bool/public"/>')
        self.assertIsNone(result['components'][0]['exported'])

    def test_custom_permissions(self):
        result = manifest_analysis(ET.fromstring('<manifest xmlns:android="http://schemas.android.com/apk/res/android"><permission android:name="p.NORMAL"/><permission android:name="p.SIG" android:protectionLevel="0x12"/></manifest>'))
        self.assertTrue(result['permissions'][0]['weak'])
        self.assertFalse(result['permissions'][1]['weak'])


class CollectionTests(unittest.TestCase):
    def test_wildcard_listeners(self):
        text = 'tcp LISTEN 0 10 0.0.0.0:5555 0.0.0.0:*\ntcp LISTEN 0 10 127.0.0.1:8000 0.0.0.0:*\nudp UNCONN 0 0 [::]:5353 [::]:*'
        self.assertEqual(len(wildcard_listeners(text)), 2)

    def test_log_mentions_of_errors_are_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            c = Context(argparse.Namespace(timeout=1), Path(tmp))
            c.start('test', 'test')
            value = c.command([sys.executable, '-c', 'print("09-05 12:00 app: password not found")'])
            self.assertIsNotNone(value)

    def test_secret_values_not_reported(self):
        secret = 'password=supersecret123'
        matches = detect(secret)
        self.assertEqual(matches[0]['kind'], 'credential assignment')
        self.assertNotIn('supersecret', json.dumps(matches))

    def test_patch_dates(self):
        self.assertEqual(patch_age('2026-01-01', date(2026, 1, 31)), 30)
        with self.assertRaises(ValueError):
            patch_age('garbage', date.today())

    def test_timeout_keeps_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'out.txt'
            result = execute([sys.executable, '-c', 'import time; print("evidence", flush=True); time.sleep(5)'], .1, path)
            self.assertTrue(result['timed_out'])
            self.assertIn('evidence', path.read_text())

    def test_denied_not_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            c = Context(argparse.Namespace(timeout=1), Path(tmp))
            c.start('test', 'test')
            value = c.command([sys.executable, '-c', 'print("Permission denied")'])
            self.assertIsNone(value)
            self.assertEqual(c.result['status'], 'partial')

    def test_all_modules_with_fake_adb(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            adb = tmp / 'adb'
            adb.write_text('''#!/usr/bin/env python3
import sys
args = sys.argv[1:]
if args == ['devices']:
    print('List of devices attached\\nFAKE123\\tdevice')
else:
    cmd = args[-1]
    if cmd == 'pm list packages -f':
        print('package:/system/priv-app/Test/Test.apk=test.app')
    elif 'getprop ro.build.version.security_patch' == cmd:
        print('2020-01-01')
    elif cmd == 'getprop ro.boot.flash.locked':
        print('0')
    elif cmd == 'getenforce':
        print('Enforcing')
    elif cmd.startswith('logcat'):
        print('password=not-a-real-password')
    elif cmd.startswith('getprop') or cmd.startswith('settings'):
        print('null')
    elif cmd.startswith('ls -1 '):
        print('Permission denied')
    else:
        print('fixture evidence')
''')
            adb.chmod(0o700)
            data = tmp / 'data'
            self.assertEqual(main(['scan', '--adb', str(adb), '--data-dir', str(data)]), 0)
            run = next(data.iterdir())
            doc = json.loads((run / 'report.json').read_text())
            self.assertEqual(len(doc['modules']), 20)
            self.assertEqual(doc['status'], 'partial')
            titles = [f['title'] for m in doc['modules'] for f in m['findings']]
            self.assertIn('Bootloader reports unlocked', titles)
            self.assertIn('Security patch exceeds age policy', titles)
            self.assertNotIn('not-a-real-password', (run / 'report.json').read_text())
            self.assertTrue((run / 'inventory.json').is_file())
            self.assertTrue((run / 'capabilities.json').is_file())
            self.assertIn('device', doc['capabilities'])
            self.assertTrue((run / 'report.txt').is_file())
            self.assertEqual(stat.S_IMODE((run / 'report.json').stat().st_mode), 0o600)
            for module in doc['modules']:
                for evidence in module['evidence']:
                    self.assertTrue((run / evidence['path']).is_file())

    def test_missing_adb_still_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(main(['scan', '--adb', '/nonexistent/adb', '--data-dir', tmp]), 1)
            doc = json.loads(next(Path(tmp).glob('*/report.json')).read_text())
            self.assertEqual(doc['status'], 'error')


if __name__ == '__main__':
    unittest.main()
