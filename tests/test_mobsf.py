import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

from android_audit.core import Context
from android_audit.integrations import mobsf_scan, mobsf_upload_folder
from android_audit.mobsf_worker import run, valid_report


class RequestTimeout(Exception):
    pass


class ConnectionFailure(Exception):
    pass


REQUESTS = NS(Timeout=RequestTimeout, ConnectionError=ConnectionFailure)
MD5 = hashlib.md5(b'apk', usedforsecurity=False).hexdigest()
SHA256 = hashlib.sha256(b'apk').hexdigest()


def report():
    return {'md5': MD5, 'sha256': SHA256, 'package_name': 'test.app', 'permissions': {},
            'manifest_analysis': [], 'code_analysis': {}, 'certificate_analysis': {}}


class Session:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        endpoint, value = self.responses.pop(0)
        assert url.endswith('/' + endpoint), url
        assert kwargs['allow_redirects'] is False
        assert kwargs['timeout'] > 0
        if isinstance(value, Exception):
            raise value
        code, body = value
        return NS(status_code=code, json=lambda: body)


class MobSFTests(unittest.TestCase):
    def workflow(self, responses, budget=30):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            apk = output / 'base.apk'
            apk.write_bytes(b'apk')
            args = NS(apk=apk, output=output, url='https://mobsf.test', budget=budget, timeout=2, poll_seconds=1)
            now = [0]
            def sleep(seconds):
                now[0] += seconds
            session = Session(responses)
            with patch.dict('sys.modules', {'requests': REQUESTS}):
                code = run(args, session, clock=lambda: now[0], sleep=sleep)
            files = {p.name: json.loads(p.read_text()) for p in output.glob('*.json')}
            return code, files, session.calls

    def start(self, scan=None):
        return [('upload', (200, {'hash': MD5})), ('scan', (200, scan or report()))]

    def test_synchronous_scan_retains_validated_report(self):
        code, files, calls = self.workflow(self.start() + [('report_json', (200, report()))])
        self.assertEqual(code, 0)
        self.assertEqual(files['status.json']['status'], 'completed')
        self.assertEqual(files['report_json.json']['sha256'], SHA256)
        self.assertEqual(len(calls), 3)

    def test_queue_waits_for_matching_task_then_report(self):
        pending = {'task_id': 'task', 'checksum': MD5, 'completed_at': None}
        done = dict(pending, completed_at='today', status='Success')
        responses = self.start({'task_id': 'task', 'message': 'queued'}) + [
            ('tasks', (200, [dict(done, task_id='other')])),
            ('tasks', (200, [pending])), ('tasks', (200, [done])),
            ('report_json', (404, {'report': 'Report not Found'})),
            ('report_json', (200, report()))]
        code, files, calls = self.workflow(responses)
        self.assertEqual(code, 0)
        self.assertEqual(files['status.json']['task_id'], 'task')
        self.assertEqual(len(calls), 7)

    def test_failed_task_does_not_fetch_report(self):
        task = {'task_id': 'task', 'checksum': MD5, 'completed_at': 'today', 'status': 'Scan Timeout'}
        code, files, calls = self.workflow(self.start({'task_id': 'task'}) + [('tasks', (200, [task]))])
        self.assertEqual(code, 1)
        self.assertNotIn('report_json.json', files)
        self.assertEqual(files['status.json']['status'], 'failed')

    def test_deadline_while_report_pending(self):
        responses = self.start() + [('report_json', (404, {'report': 'Report not Found'}))] * 2
        code, files, calls = self.workflow(responses, budget=2)
        self.assertEqual(code, 1)
        self.assertEqual(files['status.json']['status'], 'timed_out')
        self.assertNotIn('report_json.json', files)

    def test_scan_timeout_does_not_resubmit(self):
        responses = [('upload', (200, {'hash': MD5})), ('scan', RequestTimeout('secret')),
                     ('report_json', (503, {})), ('report_json', (200, report()))]
        code, files, calls = self.workflow(responses)
        self.assertEqual(code, 0)
        self.assertEqual(sum(url.endswith('/scan') for url, _ in calls), 1)
        self.assertNotIn('secret', json.dumps(files))

    def test_invalid_report_never_becomes_analysis_evidence(self):
        for body in ({}, {'status': 'completed'}, {'error': 'failed'}, dict(report(), sha256='0' * 64), dict(report(), md5=None)):
            self.assertFalse(valid_report(body, MD5, SHA256))
            code, files, calls = self.workflow(self.start() + [('report_json', (200, body))])
            self.assertEqual(code, 1)
            self.assertNotIn('report_json.json', files)

    def test_http_errors_redirects_and_hash_mismatch_stop(self):
        for response in ((401, {'error': 'unauthorized'}), (302, {}), (200, {'hash': '0' * 32})):
            code, files, calls = self.workflow([('upload', response)])
            self.assertEqual(code, 1)
            self.assertEqual(len(calls), 1)
            self.assertIn('0001-upload.json', files)

    def test_report_transport_error_retries(self):
        code, files, calls = self.workflow(self.start() + [
            ('report_json', ConnectionFailure('secret')), ('report_json', (200, report()))])
        self.assertEqual(code, 0)
        self.assertNotIn('secret', json.dumps(files))

    def context(self, tmp):
        args = argparse.Namespace(serial='device', user=0, mobsf_url='https://mobsf.test',
            integration_timeout=10, timeout=2, mobsf_poll_seconds=1)
        c = Context(args, Path(tmp))
        c.start('app_extraction', 'running_applications')
        apk = c.root / 'apks/test.app/000.apk'
        apk.parent.mkdir(parents=True)
        apk.write_bytes(b'apk')
        return c, apk

    def test_parent_records_hard_timeout_and_no_external_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            c, apk = self.context(tmp)
            def command(argv, label, timeout):
                self.assertNotIn('secret', argv)
                self.assertEqual(timeout, 10)
                c.result['evidence'].append({'label': label, 'timed_out': True})
            c.command = command
            with patch.dict(os.environ, {'MOBSF_API_KEY': 'secret'}), patch('importlib.util.find_spec', return_value=True):
                mobsf_scan(c, apk)
            path = c.root / 'integrations/mobsf/test.app-000/status.json'
            self.assertEqual(json.loads(path.read_text())['status'], 'timed_out')
            self.assertEqual(c.result['analysis_checks'][0]['status'], 'not_evaluated')
            self.assertFalse(any(e.get('kind') == 'external_analysis' for e in c.result['evidence']))

    def test_missing_key_is_explicit_coverage_gap(self):
        with tempfile.TemporaryDirectory() as tmp:
            c, apk = self.context(tmp)
            with patch.dict(os.environ, {}, clear=True):
                mobsf_scan(c, apk)
            self.assertEqual(c.result['analysis_checks'][0]['status'], 'not_evaluated')

    def test_upload_folder_selects_only_apks(self):
        with tempfile.TemporaryDirectory() as tmp:
            c, _ = self.context(tmp)
            folder = Path(tmp) / 'mobsf-upload'
            folder.mkdir()
            (folder / 'one.apk').write_bytes(b'one')
            (folder / 'TWO.APK').write_bytes(b'two')
            (folder / 'notes.txt').write_text('ignore')
            c.args.mobsf_upload_dir = folder
            selected = []
            with patch('android_audit.integrations.mobsf_scan', side_effect=lambda context, apk, **kwargs: selected.append(apk.name)):
                mobsf_upload_folder(c)
            self.assertEqual(selected, ['TWO.APK', 'one.apk'])
            self.assertEqual(c.result['analysis_checks'][0]['status'], 'evaluated')

    def test_upload_folder_empty_is_not_evaluated(self):
        with tempfile.TemporaryDirectory() as tmp:
            c, _ = self.context(tmp)
            folder = Path(tmp) / 'mobsf-upload'
            folder.mkdir()
            c.args.mobsf_upload_dir = folder
            mobsf_upload_folder(c)
            self.assertEqual(c.result['analysis_checks'][0]['status'], 'not_evaluated')

    def test_parent_accepts_only_validated_worker_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            c, apk = self.context(tmp)
            def command(argv, label, timeout):
                output = Path(argv[argv.index('--output') + 1])
                (output / 'status.json').write_text(json.dumps({'status': 'completed', 'md5': MD5, 'sha256': SHA256}))
                (output / 'report_json.json').write_text(json.dumps(report()))
            c.command = command
            with patch.dict(os.environ, {'MOBSF_API_KEY': 'secret'}), patch('importlib.util.find_spec', return_value=True):
                mobsf_scan(c, apk)
            self.assertEqual(c.result['analysis_checks'][0]['status'], 'evaluated')
            self.assertEqual(sum(e.get('kind') == 'external_analysis' for e in c.result['evidence']), 1)

    def test_parent_marks_interruption_before_reraising(self):
        with tempfile.TemporaryDirectory() as tmp:
            c, apk = self.context(tmp)
            c.command = lambda *args: (_ for _ in ()).throw(KeyboardInterrupt())
            with patch.dict(os.environ, {'MOBSF_API_KEY': 'secret'}), patch('importlib.util.find_spec', return_value=True):
                with self.assertRaises(KeyboardInterrupt):
                    mobsf_scan(c, apk)
            path = c.root / 'integrations/mobsf/test.app-000/status.json'
            self.assertEqual(json.loads(path.read_text())['status'], 'interrupted')
            self.assertEqual(c.result['analysis_checks'][0]['status'], 'not_evaluated')
