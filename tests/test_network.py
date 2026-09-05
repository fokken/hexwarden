import unittest

from android_audit.modules.network import (
    correlate_listeners, firewall_summary, parse_interfaces, parse_listeners,
    parse_package_uids, parse_processes, parse_routes,
)
from android_audit.modules.passive_network import parse_cleartext_rows
from android_audit.modules.passive_network import pcap_header
from pathlib import Path
import tempfile


class NetworkParsingTests(unittest.TestCase):
    def test_listener_process_and_package_correlation(self):
        listeners = parse_listeners(
            'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n'
            'tcp LISTEN 0 128 0.0.0.0:5555 0.0.0.0:* users:(("demo",pid=42,fd=3))\n'
            'udp UNCONN 0 0 192.168.1.2:5353 0.0.0.0:*')
        self.assertEqual(len(listeners), 2)
        self.assertTrue(listeners[0]['wildcard'])
        processes = parse_processes('PID UID NAME\n42 u0_a123 demo')
        packages = parse_package_uids('package:com.example.demo uid:10123\n')
        correlated = correlate_listeners(listeners, processes)
        correlated[0]['process_identity']['packages'] = packages['10123']
        self.assertEqual(correlated[0]['pid'], 42)
        self.assertEqual(correlated[0]['process_identity']['packages'], ['com.example.demo'])
        self.assertFalse(correlated[1]['wildcard'])

    def test_process_parser_accepts_uid_forms(self):
        rows = parse_processes('PID UID NAME\n12 1000 system_server\n13 uid=1013 radio')
        self.assertEqual(rows[12]['uid'], '1000')
        self.assertEqual(rows[13]['uid'], '1013')

    def test_interface_and_route_context(self):
        interfaces = parse_interfaces('2: wlan0: <BROADCAST,UP,LOWER_UP>\n    inet 192.168.1.5/24\n    inet6 fe80::1/64')
        self.assertEqual(interfaces[0]['name'], 'wlan0')
        self.assertEqual(interfaces[0]['addresses'], ['192.168.1.5/24', 'fe80::1/64'])
        routes = parse_routes('default via 192.168.1.1 dev wlan0 metric 600\n10.0.0.0/8 dev rmnet0')
        self.assertEqual(routes[0]['interface'], 'wlan0')
        self.assertEqual(routes[0]['gateway'], '192.168.1.1')
        self.assertTrue(routes[0]['default'])

    def test_firewall_summary(self):
        summary = firewall_summary(':INPUT ACCEPT [0:0]\n:OUTPUT DROP [0:0]\n-A INPUT -p tcp --dport 443 -j ACCEPT\n')
        self.assertEqual(summary['default_policies'], {'INPUT': 'ACCEPT', 'OUTPUT': 'DROP'})
        self.assertEqual(summary['rule_count'], 1)

    def test_cleartext_rows_omit_payload(self):
        rows = parse_cleartext_rows('12\tHTTP\tGET /secret\n13\tFTP\tRETR file\n')
        self.assertEqual([row['frame'] for row in rows], [12, 13])
        self.assertNotIn('secret', str(rows))

    def test_pcap_header_accepts_pcap_and_pcapng(self):
        with tempfile.TemporaryDirectory() as tmp:
            pcap = Path(tmp) / 'capture.pcap'
            pcap.write_bytes(b'\xd4\xc3\xb2\xa1' + b'\0' * 20)
            pcapng = Path(tmp) / 'capture.pcapng'
            pcapng.write_bytes(b'\x0a\x0d\x0d\x0a' + b'\0' * 20)
            self.assertTrue(pcap_header(pcap))
            self.assertTrue(pcap_header(pcapng))

    def test_pcap_header_rejects_empty_or_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'capture'
            path.write_text('tcpdump failed')
            self.assertFalse(pcap_header(path))


if __name__ == '__main__':
    unittest.main()
