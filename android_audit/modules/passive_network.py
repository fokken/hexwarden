import shutil
CATEGORY = 'networking'

def run(c):
    if not c.args.capture_seconds:
        c.result['status'] = 'skipped'
        c.note('Enable --capture-seconds N for bounded passive capture; requires device tcpdump and timeout, usually --root.')
        return
    # Device timeout stops the remote process even if the ADB connection disappears.
    c.shell(f'timeout -s INT {c.args.capture_seconds} tcpdump -i any -p -s 0 -U -w -',
            'traffic', root=c.args.root, timeout=c.args.capture_seconds + 15, binary=True)
    evidence = c.result['evidence']
    if not evidence:
        return
    record = evidence[-1]
    path = c.root / record['path']
    with path.open('rb') as stream:
        magic = stream.read(4)
    if magic not in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d', b'\x0a\x0d\x0d\x0a'):
        c.note('No valid PCAP header: capture failed or command produced non-PCAP output.')
        return
    if shutil.which('tshark'):
        value = c.command(['tshark', '-n', '-r', str(path), '-Y',
            'http.request or ftp or telnet or smtp or pop or imap', '-T', 'fields',
            '-e', 'frame.number', '-e', 'ip.src', '-e', 'ipv6.src', '-e', 'tcp.dstport',
            '-e', '_ws.col.Protocol'], 'cleartext_protocols')
        if value and value.strip():
            c.finding('Potential cleartext application traffic', 'Protocol candidates found; inspect packets to distinguish cleartext payload from STARTTLS negotiation.', 'medium')
    else:
        c.note('Install host tshark to analyze captured protocols; PCAP retained.')
    c.note('Linux any covers visible interfaces in this network namespace, not offloaded traffic or other namespaces. No decryption; protocol heuristics are incomplete. A timeout exit can be expected for a bounded capture; validate PCAP completeness.')
