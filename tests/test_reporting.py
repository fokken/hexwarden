import argparse
import json
from pathlib import Path
import tempfile
import unittest
from android_audit.core import Context
from android_audit.findings import RULES, instance_id
from android_audit.reporting import module_coverage, summarize
from android_audit.cli import report


class ReportingTests(unittest.TestCase):
    def context(self, tmp):
        context = Context(argparse.Namespace(serial='device', user=0), Path(tmp))
        context.start('test', 'test')
        return context

    def evidence(self, c, name='raw.txt', ok=True, truncated=False):
        (c.root / name).write_text('fixture\n')
        c.result['evidence'].append({'path': name, 'returncode': 0 if ok else 1,
                                    'ok': ok, 'analysis_truncated': truncated})
        c.latest_evidence = [{'path': name}]

    def test_collection_only_is_not_completed_analysis(self):
        with tempfile.TemporaryDirectory() as tmp:
            c = self.context(tmp)
            self.evidence(c)
            coverage = module_coverage(c.result)
            self.assertEqual(coverage['collection']['status'], 'completed')
            self.assertEqual(coverage['analysis']['status'], 'not_performed')
            self.assertTrue(coverage['manual_verification']['required'])

    def test_zero_findings_still_records_evaluated_checks(self):
        with tempfile.TemporaryDirectory() as tmp:
            c = self.context(tmp)
            self.evidence(c)
            c.check('a_real_check', True)
            coverage = module_coverage(c.result)
            self.assertEqual(coverage['analysis']['status'], 'completed')
            self.assertEqual(c.result['findings'], [])

    def test_manual_scope_does_not_erase_completed_analysis(self):
        with tempfile.TemporaryDirectory() as tmp:
            c = self.context(tmp)
            self.evidence(c)
            c.check('heuristic', True)
            c.note('Independent trust verification required.')
            coverage = module_coverage(c.result)
            self.assertEqual(coverage['analysis']['status'], 'completed')
            self.assertEqual(coverage['collection']['status'], 'completed')
            self.assertTrue(coverage['manual_verification']['required'])

    def test_blocked_checks_and_skipped_commands_count_separately(self):
        with tempfile.TemporaryDirectory() as tmp:
            c = self.context(tmp)
            self.evidence(c)
            c.check('available', True)
            c.skip('ss', 'listeners', 'unavailable')
            c.check('listeners', False)
            coverage = module_coverage(c.result)
            self.assertEqual(coverage['collection']['skipped_commands'], 1)
            self.assertEqual(coverage['analysis']['not_evaluated_checks'], 1)
            self.assertEqual(coverage['analysis']['status'], 'partial')

    def test_truncation_prevents_complete_analysis(self):
        with tempfile.TemporaryDirectory() as tmp:
            c = self.context(tmp)
            self.evidence(c, truncated=True)
            c.check('heuristic', True)
            self.assertEqual(module_coverage(c.result)['analysis']['status'], 'partial')

    def test_high_confidence_candidate_is_not_confirmed(self):
        with tempfile.TemporaryDirectory() as tmp:
            c = self.context(tmp)
            self.evidence(c)
            c.finding('HW-APP-002', {'package': 'test.app', 'name': '.Provider'}, 'medium', 'high')
            finding = c.result['findings'][0]
            self.assertEqual(finding['classification'], 'review_candidate')
            self.assertEqual(finding['verification_status'], 'pending')
            self.assertTrue(finding['remediation'])
            self.assertTrue(finding['verification'])

    def test_id_ignores_evidence_filename_and_transient_detail(self):
        asset = {'device': 'd', 'package': 'test.app'}
        self.assertEqual(instance_id('HW-APP-004', asset), instance_id('HW-APP-004', dict(reversed(list(asset.items())))))
        self.assertNotEqual(instance_id('HW-APP-004', asset), instance_id('HW-APP-004', {'device': 'other', 'package': 'test.app'}))
        with tempfile.TemporaryDirectory() as tmp:
            c = self.context(tmp)
            self.evidence(c, 'first.txt')
            c.finding('HW-PATCH-001', 'age 100 days', asset=asset)
            self.evidence(c, 'second.txt')
            c.finding('HW-PATCH-001', 'age 101 days', asset=asset)
            self.assertEqual(len(c.result['findings']), 1)
            self.assertEqual(len(c.result['findings'][0]['evidence']), 2)

    def test_finding_does_not_reference_unrelated_earlier_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            c = self.context(tmp)
            self.evidence(c, 'unrelated.txt')
            self.evidence(c, 'matching.txt')
            c.finding('HW-LOG-001', 'candidate', evidence=[{'path': 'matching.txt', 'locator': {'lines': [1]}}])
            self.assertEqual(c.result['findings'][0]['evidence'], [{'path': 'matching.txt', 'locator': {'lines': [1]}}])

    def test_summary_tracks_not_started_and_text_matches_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            c = self.context(tmp)
            self.evidence(c)
            c.check('inspection', True)
            c.finding('HW-LOG-001', {'values': 'omitted'}, 'medium')
            document = {'schema_version': 2, 'run_id': 'fixture', 'device': 'd', 'status': 'partial',
                        'modules': [c.result], 'requested_modules': ['test', 'never_started']}
            report(c.root, document)
            decoded = json.loads((c.root / 'report.json').read_text())
            text = (c.root / 'report.txt').read_text()
            self.assertEqual(decoded['summary']['requested_modules_not_started'], ['never_started'])
            self.assertEqual(decoded['summary']['by_classification'], {'review_candidate': 1})
            for phrase in ('HW-LOG-001', 'Action:', 'Verify:', 'raw.txt', 'never_started'):
                self.assertIn(phrase, text)

    def test_interruption_cannot_look_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            c = self.context(tmp)
            self.evidence(c)
            c.check('first', True)
            c.result['interrupted'] = True
            self.assertEqual(module_coverage(c.result)['analysis']['status'], 'partial')

    def test_catalog_has_unique_ids_and_guidance(self):
        from android_audit.findings import RULE_DATA
        self.assertEqual(len(RULE_DATA), len(RULES))
        for rule in RULES.values():
            self.assertTrue(rule['remediation'])
            self.assertTrue(rule['verification'])
            self.assertIn(rule['classification'], ('observation', 'review_candidate', 'confirmed_weakness'))
