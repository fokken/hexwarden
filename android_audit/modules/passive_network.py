"""Opt-in bounded packet capture and cleartext protocol review."""

import json
import shutil

from ..core import write_json

CATEGORY = 'networking'
PROTOCOL_FILTER = ('tcp.payload and (http or ftp or telnet or smtp or pop or imap or '
                   'irc or ldap or mqtt or xmpp or sip or rtsp)')
PCAP_MAGICS = (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x4d\x3c\xb2\xa1',
               b'\xa1\xb2\x3c\x4d', b'\x0a\x0d\x0d\x0a')


def parse_cleartext_rows(value):
    rows = []
    for line in value.splitlines():
        fields = line.split('\t')
        if len(fields) < 2 or not fields[0].isdigit():
            continue
        # Do not retain tshark's Info column: it can contain URLs, commands or secrets.
        rows.append({'frame': int(fields[0]), 'protocol': fields[1]})
    return rows


def pcap_header(path):
    with path.open('rb') as stream:
        return stream.read(4) in PCAP_MAGICS


def run(c):
    if not c.args.capture_seconds:
        c.result['status'] = 'skipped'
        c.check('pcap_capture', False, reason='Capture not requested; use --capture-seconds N.')
        c.note('Enable --capture-seconds N for a retained PCAP and automatic protocol analysis.')
        return
    snaplen = c.args.capture_snaplen or 0
    command = (f'timeout -s INT {c.args.capture_seconds} tcpdump -i {c.args.capture_interface} '
               f'-p -s {snaplen} -U -w -')
    c.shell(command, 'traffic', root=c.args.root,
            timeout=c.args.capture_seconds + 15, binary=True)
    traffic = next((item for item in reversed(c.result['evidence']) if item.get('label') == 'traffic'), None)
    if traffic is None:
        c.check('pcap_capture', False, reason='Capture command produced no retained artifact.')
        return
    path = c.root / traffic['path']
    valid = path.is_file() and path.stat().st_size >= 24 and pcap_header(path)
    metadata = {'requested_seconds': c.args.capture_seconds,
                'interface': c.args.capture_interface, 'snaplen': snaplen,
                'path': traffic['path'], 'size_bytes': path.stat().st_size if path.exists() else 0,
                'command_returncode': traffic.get('returncode'),
                'timeout_observed': traffic.get('timed_out', False), 'valid_header': valid,
                'analysis': 'pending' if valid else 'not_started'}
    metadata_path = c.directory / 'capture-metadata.json'
    write_json(metadata_path, metadata)
    c.result['evidence'].append({'path': str(metadata_path.relative_to(c.root)), 'kind': 'derived'})
    c.result['capture'] = metadata
    c.check('pcap_capture', valid, evidence=[{'path': traffic['path']}],
            reason='No complete PCAP header or capture artifact was retained.' if not valid else None)
    if not valid:
        c.note('No valid PCAP header: capture failed or produced an incomplete artifact; inspect raw stdout/stderr.')
        return
    # timeout commonly returns a non-zero code after sending the intended stop signal;
    # a valid header and retained file are the authoritative capture evidence.
    if traffic.get('returncode') not in (0, 124, 130) and not traffic.get('timed_out'):
        c.note(f"tcpdump exited with return code {traffic.get('returncode')}; valid PCAP retained, inspect stderr for completeness.")
    if not shutil.which('tshark'):
        metadata['analysis'] = 'unavailable'
        write_json(metadata_path, metadata)
        c.check('cleartext_protocol_heuristics', False, reason='Host tshark unavailable.')
        c.note('Install host tshark to analyze the retained PCAP; the complete capture remains available for manual review.')
        return
    value = c.command(['tshark', '-n', '-r', str(path), '-Y', PROTOCOL_FILTER,
        '-T', 'fields', '-E', 'separator=\t', '-E', 'quote=d',
        '-e', 'frame.number', '-e', '_ws.col.Protocol'], 'cleartext_protocols')
    rows = parse_cleartext_rows(value or '')
    metadata['analysis'] = 'completed' if value is not None else 'failed'
    metadata['cleartext_candidate_frames'] = len(rows)
    write_json(metadata_path, metadata)
    c.check('cleartext_protocol_heuristics', value is not None,
            evidence=c.evidence_for('cleartext_protocols'),
            reason='tshark returned no analyzable output.' if value is None else None)
    if rows:
        c.finding('HW-NET-003', {'protocols': sorted({row['protocol'] for row in rows}),
                    'frame_count': len(rows), 'frames': [row['frame'] for row in rows]}, 'medium',
                    evidence=[{'path': traffic['path'], 'locator': {'frames': [row['frame'] for row in rows]}},
                              *c.evidence_for('cleartext_protocols')])
    c.note('The retained PCAP is the primary evidence artifact. The tshark filter requires application payload bytes and flags protocol candidates; encrypted sessions, STARTTLS transitions, QUIC and proprietary protocols need additional review. No decryption is attempted.')
