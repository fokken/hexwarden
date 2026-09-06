import json
from pathlib import Path
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

from android_audit.core import Context
from android_audit.modules.radamsa_fuzz import parse_target, run


class RadamsaTests(unittest.TestCase):
    def test_target_parser_requires_literal_ip_and_port(self):
        self.assertEqual(parse_target('192.0.2.10:443'), ('192.0.2.10', 443))
        self.assertEqual(parse_target('[2001:db8::1]:53'), ('2001:db8::1', 53))
        for value in ('example.test:443', '192.0.2.10', '192.0.2.10:0', '[::1]'):
            with self.assertRaises(ValueError):
                parse_target(value)

    def test_campaign_journals_payload_before_and_after_send(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            seed = root / 'seed.bin'
            seed.write_bytes(b'hello')
            args = NS(radamsa_fuzz=True, radamsa_seed_file=[seed],
                      radamsa_target=['192.0.2.10:9000'], radamsa_protocol='tcp',
                      radamsa_count=1, radamsa_timeout=2, radamsa_delay_ms=0,
                      radamsa_max_payload=64, radamsa_max_seconds=60)
            c = Context(args, root)
            c.start('radamsa_fuzz', 'networking')
            c.capabilities = {'host_tools': {'radamsa': {'path': '/usr/bin/radamsa'}}}
            completed = NS(returncode=0, stdout=b'\x00\xff', stderr=b'')
            with patch('android_audit.modules.radamsa_fuzz.subprocess.run', return_value=completed), \
                 patch('android_audit.modules.radamsa_fuzz._send', return_value={'status': 'sent', 'response_length': 0, 'duration_ms': 1.0}):
                run(c)
            lines = (c.directory / 'radamsa-fuzz.jsonl').read_text().splitlines()
            self.assertEqual(len(lines), 2)
            prepared = json.loads(lines[0])
            completed = json.loads(lines[1])
            self.assertEqual(prepared['payload_hex'], '00ff')
            self.assertEqual(prepared['status'], 'prepared')
            self.assertEqual(completed['status'], 'sent')
            self.assertEqual(c.result['status'], 'collected')


if __name__ == '__main__':
    unittest.main()
