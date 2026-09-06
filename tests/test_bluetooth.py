import argparse
import asyncio
from contextlib import redirect_stderr
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

from android_audit.bluetooth_host import connect_classic, enumerate_ble, fuzz_payloads
from android_audit.cli import bluetooth_mac, main
from android_audit.core import Context
from android_audit.modules.bluetooth import host_tests, parse_sdp

MAC = 'AA:BB:CC:DD:EE:FF'
SDP = '''Browsing AA:BB:CC:DD:EE:FF ...
Service Name: Serial Port
Service RecHandle: 0x10001
Protocol Descriptor List:
  "L2CAP" (0x0100)
  "RFCOMM" (0x0003)
    Channel: 7
Profile Descriptor List:
  "Serial Port" (0x1101)
    Version: 0x0100
Service Name: Audio
Service RecHandle: 0x10002
Protocol Descriptor List:
  "L2CAP" (0x0100)
    PSM: 0x0019
  "AVDTP" (0x0019)
    Version: 0x0103
'''


class SDPTests(unittest.TestCase):
    def test_record_and_endpoint_association(self):
        records = parse_sdp(SDP)
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]['endpoints'], [{'protocol': 'rfcomm', 'endpoint': 7}])
        self.assertEqual(records[1]['endpoints'], [{'protocol': 'l2cap', 'endpoint': 25}])

    def test_invalid_channels_and_profile_fields_not_probed(self):
        text = SDP.replace('Channel: 7', 'Channel: 31').replace('PSM: 0x0019', 'PSM: 2')
        text += '\nProfile Descriptor List:\n  "RFCOMM" (0x0003)\n    Channel: 8\n'
        self.assertFalse(any(r['endpoints'] for r in parse_sdp(text)))

    def test_nameless_records_and_unknown_output(self):
        records = parse_sdp('Service RecHandle: 0x1\nProtocol Descriptor List:\n "RFCOMM" (0x0003)\n Channel: 1\nService RecHandle: 0x2\n')
        self.assertEqual(len(records), 2)
        self.assertEqual(parse_sdp('Failed to connect to SDP server'), [])

    def test_mac_validation(self):
        self.assertEqual(bluetooth_mac(MAC.lower()), MAC)
        for value in ['AA:BB', MAC + '; echo hello', '--help']:
            with self.assertRaises(argparse.ArgumentTypeError):
                bluetooth_mac(value)

    def test_fuzz_payloads_are_bounded_and_deterministic(self):
        first = fuzz_payloads(64)
        self.assertEqual(first, fuzz_payloads(64))
        self.assertLessEqual(len(first), 64)
        self.assertTrue(all(0 < len(payload) <= 64 for payload in first))

    def test_cli_rejects_incompatible_options_before_adb(self):
        for args in [['--bt-read'], ['--bt-mac', MAC, '--modules', 'usb'],
                     ['--bt-mac', MAC, '--bt-mode', 'classic', '--bt-pair'],
                     ['--bt-mac', MAC, '--bt-mode', 'ble', '--bt-connect-classic']]:
            with self.subTest(args=args), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                main(['scan', *args])
            self.assertEqual(error.exception.code, 2)


class BLETests(unittest.IsolatedAsyncioTestCase):
    def dependencies(self, *, denied=False):
        self.calls = []
        self.closed = False
        owner = self
        class Scanner:
            @staticmethod
            async def find_device_by_address(mac, timeout):
                owner.calls.append(('scan', mac))
                return NS(address=mac, name='Fixture')
        class Client:
            def __init__(self, device, **kwargs):
                owner.calls.append(('client', kwargs))
                self.is_connected = True
                self.services = [NS(uuid='service', handle=1, characteristics=[
                    NS(uuid='char', handle=2, properties=['read', 'write-without-response'],
                       descriptors=[NS(uuid='descriptor', handle=3)])])]
            async def __aenter__(self):
                return self
            async def __aexit__(self, *args):
                owner.closed = True
            async def read_gatt_char(self, char):
                owner.calls.append(('read', char.handle))
                if denied:
                    raise PermissionError('authentication required')
                return b'sensitive-value'
            async def write_gatt_char(self, char, payload, response=True):
                owner.calls.append(('write', char.handle, bytes(payload), response))
            async def start_notify(self, char, callback):
                owner.calls.append(('notify_start', char.handle))
                callback(char, b'event')
            async def stop_notify(self, char):
                owner.calls.append(('notify_stop', char.handle))
        return Scanner, Client

    async def test_discovery_does_not_read_or_pair(self):
        scanner, client = self.dependencies()
        result = await enumerate_ble(MAC, 2, scanner=scanner, client_factory=client)
        self.assertEqual(result['status'], 'collected')
        self.assertTrue(result['services'][0]['characteristics'][0]['advertises_write'])
        self.assertFalse(any(call[0] == 'read' for call in self.calls))
        self.assertFalse(self.calls[1][1]['pair'])
        self.assertTrue(self.closed)

    async def test_reads_and_pairing_explicit(self):
        scanner, client = self.dependencies()
        result = await enumerate_ble(MAC, 2, read=True, pair=True, scanner=scanner, client_factory=client)
        read = result['services'][0]['characteristics'][0]['read']
        self.assertEqual(bytes.fromhex(read['hex']), b'sensitive-value')
        self.assertTrue(self.calls[1][1]['pair'])
        self.assertTrue(self.closed)

    async def test_denied_read_is_partial_not_a_security_verdict(self):
        scanner, client = self.dependencies(denied=True)
        result = await enumerate_ble(MAC, 2, read=True, scanner=scanner, client_factory=client)
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['services'][0]['characteristics'][0]['read']['status'], 'failed')
        self.assertTrue(self.closed)

    async def test_scan_timeout(self):
        class SlowScanner:
            @staticmethod
            async def find_device_by_address(*args, **kwargs):
                await asyncio.sleep(2)
        _, client = self.dependencies()
        result = await enumerate_ble(MAC, .01, scanner=SlowScanner, client_factory=client)
        self.assertEqual(result['status'], 'partial')
        self.assertTrue(result['errors'])

    async def test_absent_target(self):
        class Scanner:
            @staticmethod
            async def find_device_by_address(*args, **kwargs):
                return None
        _, client = self.dependencies()
        result = await enumerate_ble(MAC, 2, scanner=Scanner, client_factory=client)
        self.assertIn('not observed', result['errors'][0])

    async def test_targeted_write_and_fuzz_record_metadata_only(self):
        scanner, client = self.dependencies()
        result = await enumerate_ble(MAC, 2, scanner=scanner, client_factory=client,
                                     write_targets=['service/char'], write_payloads=['00'],
                                     fuzz=True, fuzz_count=2)
        self.assertEqual(result['status'], 'collected')
        self.assertEqual(len(result['writes']), 2)
        self.assertTrue(all(item['status'] == 'accepted' for item in result['writes']))
        self.assertEqual(result['writes'][0]['payload_hex'], '00')
        self.assertIn('payload_hex', result['writes'][1])
        self.assertTrue(any(call[0] == 'write' for call in self.calls))

    async def test_notification_subscription_is_bounded_and_recorded(self):
        scanner, client = self.dependencies()
        # Add an indication property to the fixture characteristic.
        class NotifyClient(client):
            def __init__(self, device, **kwargs):
                super().__init__(device, **kwargs)
                self.services[0].characteristics[0].properties.append('notify')
        result = await enumerate_ble(MAC, 2, scanner=scanner, client_factory=NotifyClient,
                                     notify=True, notify_seconds=.01)
        self.assertEqual(result['status'], 'collected')
        self.assertEqual(result['notifications'][0]['status'], 'subscribed')
        self.assertEqual(result['notifications'][0]['events'][0]['length'], 5)
        self.assertTrue(any(call[0] == 'notify_stop' for call in self.calls))


class HostTests(unittest.TestCase):
    def test_socket_closes_without_sending(self):
        calls = []
        class Connection:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                calls.append('closed')
            def settimeout(self, timeout):
                calls.append(('timeout', timeout))
            def connect(self, address):
                calls.append(('connect', address))
        with patch('android_audit.bluetooth_host.sys.platform', 'linux'):
            result = connect_classic(MAC, 'rfcomm', 7, 2, socket_factory=lambda *args: Connection())
        self.assertEqual(result['status'], 'connected')
        self.assertEqual(calls, [('timeout', 2), ('connect', (MAC, 7)), 'closed'])
        self.assertFalse(result['payload_sent'])

    def test_classic_payload_is_sent_and_recorded(self):
        calls = []
        class Connection:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def settimeout(self, timeout):
                pass
            def connect(self, address):
                calls.append(('connect', address))
            def sendall(self, payload):
                calls.append(('send', bytes(payload)))
            def recv(self, size):
                return b'ok'
        with patch('android_audit.bluetooth_host.sys.platform', 'linux'):
            result = connect_classic(MAC, 'rfcomm', 7, 2, payloads=[b'probe'],
                                     socket_factory=lambda *args: Connection())
        self.assertEqual(result['payloads'][0]['status'], 'accepted')
        self.assertEqual(result['payloads'][0]['response_length'], 2)
        self.assertEqual(calls[-1], ('send', b'probe'))

    def test_module_reports_candidates_without_read_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = NS(bt_mac=MAC, bt_mode='both', bt_timeout=2,
                      bt_read=True, bt_pair=False, bt_connect_classic=True)
            c = Context(args, Path(tmp))
            c.start('bluetooth', 'wireless')
            def command(argv, label, timeout=None):
                if label == 'host_sdp':
                    return SDP
                return ''
            c.command = command
            def fake_worker(context, mode, extra=(), timeout=None):
                if mode != 'ble':
                    return {'status': 'connected', 'protocol': mode}
                return {'status': 'collected', 'services': [{'uuid': 'service', 'characteristics': [
                    {'uuid': 'char', 'handle': 2, 'properties': ['read', 'write'], 'advertises_write': True,
                     'read': {'status': 'success', 'length': 6, 'hex': '736563726574'}}]}]}
            with patch('android_audit.modules.bluetooth.shutil.which', return_value='/fixture/tool'), patch('android_audit.modules.bluetooth.worker', side_effect=fake_worker), patch('android_audit.modules.bluetooth.sys.platform', 'linux'):
                host_tests(c)
            titles = [f['title'] for f in c.result['findings']]
            self.assertIn('BLE characteristic advertises write support', titles)
            self.assertIn('Bluetooth Classic endpoint accepts host connection', titles)
            self.assertNotIn('736563726574', json.dumps(c.result))
            self.assertTrue((c.directory / 'sdp-services.json').is_file())

    def test_missing_classic_tool_is_partial(self):
        with tempfile.TemporaryDirectory() as tmp:
            c = Context(NS(bt_mac=MAC, bt_mode='classic'), Path(tmp))
            c.start('bluetooth', 'wireless')
            with patch('android_audit.modules.bluetooth.shutil.which', return_value=None):
                host_tests(c)
            self.assertEqual(c.result['status'], 'partial')
            self.assertEqual(c.result['findings'], [])


if __name__ == '__main__':
    unittest.main()
