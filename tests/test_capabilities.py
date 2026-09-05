import argparse
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from android_audit.capabilities import parse_commands, parse_services
from android_audit.core import Context


def capabilities(commands=None, root=None, services=None):
    return {'host_tools': {}, 'device': {'commands': commands or {},
        'root': root or {'status': 'not_requested', 'method': None, 'commands': {}},
        'services': services or {'status': 'unknown', 'names': []}}}


class CapabilityTests(unittest.TestCase):
    def test_partial_command_probe_is_unknown(self):
        self.assertEqual(parse_commands('HW_CAP ss unavailable\n')['ss'], 'unknown')
        self.assertEqual(parse_commands('HW_CAP ss unavailable\nHW_CAP_DONE\n')['ss'], 'unavailable')

    def test_service_inventory_requires_recognized_complete_shape(self):
        self.assertEqual(parse_services('Permission denied')['status'], 'unknown')
        self.assertEqual(parse_services('Currently running services:\n  wifi\n  usb\n')['names'], ['usb', 'wifi'])
        self.assertEqual(parse_services('Currently running services:\n wifi\n ERROR: truncated')['status'], 'unknown')

    def context(self, directory):
        c = Context(argparse.Namespace(root=True, adb='adb', serial='test', timeout=1), Path(directory))
        c.start('test', 'test')
        return c

    def test_known_missing_device_command_skips_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            c = self.context(tmp)
            c.capabilities = capabilities({'ss': 'unavailable'})
            with patch.object(c, 'command') as command:
                self.assertIsNone(c.shell('ss -lntup', 'listeners'))
                command.assert_not_called()
            self.assertIn('ss absent', c.result['skipped_checks'][0]['reason'])

    def test_unknown_capability_is_attempted(self):
        with tempfile.TemporaryDirectory() as tmp:
            c = self.context(tmp)
            c.capabilities = capabilities({'ss': 'unknown'})
            with patch.object(c, 'command', return_value='result') as command:
                self.assertEqual(c.shell('ss -lntup'), 'result')
                command.assert_called_once()

    def test_missing_service_skipped_but_root_view_not_assumed(self):
        with tempfile.TemporaryDirectory() as tmp:
            c = self.context(tmp)
            c.capabilities = capabilities(services={'status': 'collected', 'names': ['wifi']})
            with patch.object(c, 'command') as command:
                c.shell('dumpsys fingerprint')
                command.assert_not_called()

    def test_root_shell_does_not_require_su(self):
        with tempfile.TemporaryDirectory() as tmp:
            c = self.context(tmp)
            c.capabilities = capabilities(root={'status': 'available', 'method': 'adb_shell', 'commands': {}})
            with patch.object(c, 'command') as command:
                c.shell('id', root=True)
                self.assertEqual(command.call_args.args[0][-1], 'id')

    def test_root_failure_skips_privileged_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            c = self.context(tmp)
            c.capabilities = capabilities(root={'status': 'unavailable', 'method': 'su', 'commands': {}})
            with patch.object(c, 'command') as command:
                c.shell('iptables-save', root=True)
                command.assert_not_called()

    def test_missing_tcpdump_skips_capture_even_if_timeout_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            c = self.context(tmp)
            c.capabilities = capabilities({'timeout': 'available', 'tcpdump': 'unavailable'})
            with patch.object(c, 'command') as command:
                c.shell('timeout -s INT 5 tcpdump -i any -w -', binary=True)
                command.assert_not_called()
