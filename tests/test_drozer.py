import argparse
import importlib.util
import io
import json
from pathlib import Path
import shlex
import sys
import tempfile
from types import ModuleType
import unittest
from unittest.mock import patch

from android_audit.core import Context
from android_audit.drozer_checks import analyze, parse_events, run, report_uids


def load_probe():
    fake = ModuleType('drozer.modules')
    fake.Module = type('Module', (), {})
    name = 'hexwarden_test_probe'
    path = Path(__file__).resolve().parents[1] / 'android_audit/drozer_modules/audit.py'
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {'drozer.modules': fake}):
        spec.loader.exec_module(module)
    return module.Audit


class AgentTests(unittest.TestCase):
    def setUp(self):
        self.probe = load_probe()()
        self.probe.stdout = io.StringIO()

    def test_read_does_not_retain_content_and_closes(self):
        class File:
            def exists(self): return True
            def isFile(self): return True
            def isDirectory(self): return False
            def canRead(self): return True
            def canWrite(self): return False
        class Stream:
            closed = False
            def read(self): return 72
            def close(self): self.closed = True
        stream = Stream()
        self.probe.new = lambda name, arg: stream if name.endswith('FileInputStream') else File()
        result = self.probe.filesystem('/a', 'read', 10)
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['bytes_read'], 1)
        self.assertNotIn('72', json.dumps(result))
        self.assertTrue(stream.closed)

    def test_failed_open_is_not_success_despite_metadata(self):
        class File:
            def exists(self): return True
            def isFile(self): return True
            def isDirectory(self): return False
            def canRead(self): return True
            def canWrite(self): return False
        def new(name, arg):
            if name.endswith('FileInputStream'):
                raise PermissionError('denied')
            return File()
        self.probe.new = new
        self.assertEqual(self.probe.filesystem('/secret', 'read', 10)['status'], 'failed')

    def test_directory_null_is_not_empty_success(self):
        class File:
            def exists(self): return True
            def isFile(self): return False
            def isDirectory(self): return True
            def canRead(self): return False
            def canWrite(self): return False
            def list(self): return None
        self.probe.new = lambda *args: File()
        self.assertEqual(self.probe.filesystem('/private', 'list', 10)['status'], 'unavailable')

    def test_write_cleanup_after_failure(self):
        class File:
            def exists(self): return True
            def isFile(self): return False
            def isDirectory(self): return True
            def canRead(self): return True
            def canWrite(self): return True
        class Probe:
            deleted = False
            def getAbsolutePath(self): return '/tmp/hexwarden-unique.probe'
            def delete(self): self.deleted = True; return True
        probe = Probe()
        class JavaFile:
            @staticmethod
            def createTempFile(*args): return probe
        self.probe.klass = lambda *args: JavaFile
        def new(name, *args):
            if name.endswith('FileOutputStream'):
                raise OSError('failed')
            return File()
        self.probe.new = new
        result = self.probe.filesystem('/tmp', 'write', 10)
        self.assertEqual(result['status'], 'failed')
        self.assertTrue(result['cleanup_succeeded'])
        self.assertTrue(probe.deleted)
        self.assertIn('probe_created', self.probe.stdout.getvalue())

    def test_requested_permission_uses_actual_grant_result(self):
        from types import SimpleNamespace as NS
        class PM:
            def getPackageInfo(self, package, flags):
                return NS(applicationInfo=NS(uid=123), requestedPermissions=['allowed', 'denied'])
            def checkPermission(self, permission, package):
                return 0 if permission == 'allowed' else -1
        self.probe.getContext = lambda: NS(getPackageManager=lambda: PM())
        result = self.probe.package_grants('test.app')
        self.assertEqual([p['granted'] for p in result['permissions']], [True, False])

    def test_uid_probe_collects_visible_peers(self):
        from types import SimpleNamespace as NS
        info = NS(packageName='system.app', applicationInfo=NS(uid=1000, flags=1, sourceDir='/system/priv-app/Test/Test.apk'))
        installed = NS(size=lambda: 1, get=lambda index: info)
        pm = NS(getInstalledPackages=lambda flags: installed, getPackagesForUid=lambda uid: ['system.app', 'peer.app'])
        self.probe.getContext = lambda: NS(getPackageManager=lambda: pm)
        self.probe.package_uids([])
        events = parse_events(self.probe.stdout.getvalue())
        self.assertEqual(events[0]['uid'], 1000)
        self.assertTrue(events[0]['privileged_candidate'])
        self.assertEqual(events[0]['shared_packages'], ['system.app', 'peer.app'])
        self.assertEqual(events[-1]['kind'], 'uid_inventory_complete')


class OrchestrationTests(unittest.TestCase):
    def test_uid_groups_keep_users_separate_and_prioritize_privileged_peers(self):
        with tempfile.TemporaryDirectory() as tmp:
            c = self.context(tmp)
            events = [
                {'kind': 'package_uid', 'package': 'one', 'uid': 10001, 'shared_packages': ['one', 'two'], 'privileged_candidate': True},
                {'kind': 'package_uid', 'package': 'two', 'uid': 10001, 'shared_packages': ['one', 'two']},
                {'kind': 'package_uid', 'package': 'one', 'uid': 110001, 'shared_packages': ['one']},
                {'kind': 'uid_inventory_complete'}]
            report_uids(c, events, {'package': 'agent'})
            rows = json.loads((c.directory / 'shared-uids.json').read_text())
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[1]['user_id'], 1)
            self.assertFalse(rows[1]['shared'])
            self.assertEqual(len(c.result['findings']), 1)
            self.assertEqual(c.result['findings'][0]['severity'], 'medium')

    def test_missing_uid_inventory_is_not_evaluated(self):
        with tempfile.TemporaryDirectory() as tmp:
            c = self.context(tmp)
            report_uids(c, [], {})
            self.assertEqual(c.result['analysis_checks'][0]['status'], 'not_evaluated')

    def context(self, tmp):
        args = argparse.Namespace(timeout=1, integration_timeout=2, drozer_bin='drozer', user=0,
            drozer_server='127.0.0.1', package=['test.app'], max_apps=None,
            drozer_entry_limit=50, drozer_list_path=['/data'], drozer_read_path=['/a path/$(literal)'],
            drozer_write_dir=[])
        c = Context(args, Path(tmp))
        c.start('drozer', 'integrations')
        return c

    def test_cli_uses_supported_modules_and_quotes_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            c = self.context(tmp)
            commands = []
            def command(argv, label, *args, **kwargs):
                commands.append(argv)
                if label == 'drozer_cli_help': return '--no-color --no-password'
                if label == 'drozer_available_modules':
                    return ('app.package.info  Information\napp.package.shareduid  Shared UIDs\n'
                            'app.activity.info  Activities\napp.service.info  Services\n'
                            'app.provider.info  Providers\napp.broadcast.info  Broadcasts\n'
                            'hexwarden.audit  Checks\n')
                if label == 'hexwarden_audit':
                    parts = shlex.split(argv[-1])
                    self.assertIn('/a path/$(literal)', parts)
                    return 'HEXWARDEN_JSON {"kind":"identity","package":"agent","uid":123,"selinux_context":"app"}\nHEXWARDEN_JSON {"kind":"complete"}\n'
                return 'inventory'
            c.command = command
            c.setting = lambda *args: None
            c.shell = lambda *args: None
            with patch('android_audit.drozer_checks.shutil.which', return_value='/usr/bin/drozer'):
                run(c)
            self.assertTrue(all(cmd[0] == '/usr/bin/drozer' for cmd in commands))
            command_text = [cmd[-1] for cmd in commands]
            for name in ('app.package.info', 'app.package.shareduid', 'app.activity.info',
                         'app.service.info', 'app.provider.info', 'app.broadcast.info'):
                self.assertIn('run ' + name, command_text)
                self.assertTrue(any(text == 'run ' + name for text in command_text))
            self.assertFalse(any('app.package.attacksurface' in text for text in command_text))
            self.assertFalse(any('run app.service.info -a' in text for text in command_text))
            self.assertTrue((c.root / 'integrations/drozer/.drozer_config').exists())
            self.assertEqual(c.result['execution_context']['uid'], 123)

    def test_incomplete_cleanup_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            c = self.context(tmp)
            analyze(c, [{'kind': 'identity', 'uid': 123, 'selinux_context': 'app'},
                        {'kind': 'probe_created', 'path': '/tmp/hexwarden-x.probe'}])
            self.assertEqual(c.result['findings'][0]['title'], 'Drozer write probe cleanup not confirmed')
            self.assertEqual(c.result['status'], 'partial')

    def test_malformed_events_are_ignored(self):
        self.assertEqual(parse_events('banner\nHEXWARDEN_JSON invalid\nHEXWARDEN_JSON []'), [])

    def test_missing_identity_never_produces_access_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            c = self.context(tmp)
            analyze(c, [{'kind': 'filesystem', 'status': 'success', 'path': '/secret', 'action': 'read'}])
            self.assertEqual(c.result['findings'], [])
