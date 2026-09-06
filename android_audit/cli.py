from __future__ import annotations
import argparse
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import urlparse
from uuid import uuid4
from . import __version__
from .branding import BANNER
from .capabilities import discover
from .reporting import summarize
from .core import Context, inventory, write_json
from .integrations import external
from .modules import registry


def positive(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError('must be positive')
    return number


def nonnegative(value):
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError('must be zero or positive')
    return number


def bluetooth_mac(value):
    if not re.fullmatch(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', value):
        raise argparse.ArgumentTypeError('expected Bluetooth MAC AA:BB:CC:DD:EE:FF')
    return value.upper()


def bluetooth_write_target(value):
    if not re.fullmatch(r'[^/\s]+/[^/\s]+', value):
        raise argparse.ArgumentTypeError('expected SERVICE_UUID/CHARACTERISTIC_UUID')
    return value


def bluetooth_payload(value):
    if not re.fullmatch(r'(?:[0-9A-Fa-f]{2}){1,64}', value):
        raise argparse.ArgumentTypeError('expected 1-64 bytes of hexadecimal data')
    return value.lower()


def device_path(value):
    if not value.startswith('/') or any(ord(char) < 32 for char in value):
        raise argparse.ArgumentTypeError('expected an absolute device path without control characters')
    return value


def capture_interface(value):
    if not re.fullmatch(r'[A-Za-z0-9_.:-]+', value):
        raise argparse.ArgumentTypeError('expected a simple interface name such as any, wlan0 or rmnet0')
    return value


def radamsa_target(value):
    from .modules.radamsa_fuzz import parse_target
    try:
        parse_target(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc
    return value


def parser():
    p = argparse.ArgumentParser(prog='hexwarden', description='Hexwarden - modular Android security auditing over ADB')
    p.add_argument('--version', action='version', version=f'Hexwarden {__version__}')
    p.add_argument('--no-banner', action='store_true', help='suppress the ASCII banner')
    sub = p.add_subparsers(dest='action', required=True)
    listing = sub.add_parser('list', help='list modules and categories')
    scan = sub.add_parser('scan', help='collect evidence and generate reports')
    for command in (listing, scan):
        command.add_argument('--no-banner', action='store_true', default=argparse.SUPPRESS,
                             help='suppress the ASCII banner')
    scan.add_argument('--adb', default='adb')
    scan.add_argument('--serial', help='required if multiple devices are connected')
    scan.add_argument('--data-dir', type=Path, default=Path('data'))
    scan.add_argument('--modules', nargs='+', help='module names; default all')
    scan.add_argument('--category', action='append', choices=sorted({m.CATEGORY for m in registry().values()}))
    scan.add_argument('--root', action='store_true', help='use existing su for privileged collectors; never roots or restarts adbd')
    scan.add_argument('--user', type=int, default=0, help='Android user ID for settings/appops (default 0)')
    scan.add_argument('--timeout', type=positive, default=30)
    scan.add_argument('--patch-max-age', type=positive, default=90)
    scan.add_argument('--log-lines', type=positive, default=5000)
    scan.add_argument('--capture-seconds', type=positive, help='opt in to device tcpdump capture on any interface')
    scan.add_argument('--capture-interface', type=capture_interface, default='any', help='device interface for passive capture (default: any)')
    scan.add_argument('--capture-snaplen', type=int, default=0, help='tcpdump snap length in bytes; 0 keeps full packets')
    scan.add_argument('--radamsa-fuzz', action='store_true', help='run the separate, opt-in Radamsa socket fuzzing module')
    scan.add_argument('--radamsa-target', action='append', type=radamsa_target, default=[], metavar='IP:PORT',
                      help='explicit IPv4/IPv6 target; repeatable, IPv6 uses [ADDR]:PORT')
    scan.add_argument('--radamsa-protocol', choices=('tcp', 'udp'), default='tcp')
    scan.add_argument('--radamsa-seed-file', type=Path, action='append', default=[], metavar='FILE',
                      help='seed input for Radamsa; repeatable')
    scan.add_argument('--radamsa-count', type=positive, default=100, help='iterations per target (default 100)')
    scan.add_argument('--radamsa-timeout', type=positive, default=3, help='Radamsa/socket timeout in seconds')
    scan.add_argument('--radamsa-max-seconds', type=positive, default=1800, help='maximum total campaign duration (default 1800)')
    scan.add_argument('--radamsa-no-crash-monitor', action='store_true', help='disable the default ADB logcat crash monitor during Radamsa fuzzing')
    scan.add_argument('--radamsa-delay-ms', type=nonnegative, default=0, help='delay between payloads')
    scan.add_argument('--radamsa-max-payload', type=positive, default=4096, help='maximum generated payload size')
    scan.add_argument('--bt-mac', type=bluetooth_mac, help='opt in to host Bluetooth testing of this remote MAC')
    scan.add_argument('--bt-mode', choices=('both', 'classic', 'ble'), default='both')
    scan.add_argument('--bt-timeout', type=positive, default=30, help='deadline per host Bluetooth discovery phase (seconds)')
    scan.add_argument('--bt-read', action='store_true', help='attempt reads of BLE characteristics advertising read support')
    scan.add_argument('--bt-pair', action='store_true', help='request BLE pairing; may prompt and create a persistent bond')
    scan.add_argument('--bt-connect-classic', action='store_true', help='connect then close advertised RFCOMM/L2CAP endpoints; no payloads')
    scan.add_argument('--bt-write-target', action='append', type=bluetooth_write_target, default=[], metavar='SERVICE/CHARACTERISTIC',
                      help='explicit BLE characteristic target for authorization writes; repeatable')
    scan.add_argument('--bt-write-payload', action='append', type=bluetooth_payload, default=[], metavar='HEX',
                      help='hex payload for an explicit BLE write probe; repeatable')
    scan.add_argument('--bt-fuzz', action='store_true', help='run bounded deterministic BLE write probes against explicit targets')
    scan.add_argument('--bt-fuzz-count', type=positive, default=16, help='maximum deterministic BLE fuzz payloads per target (default 16)')
    scan.add_argument('--extract-apks', action='store_true')
    scan.add_argument('--privileged-api-exclude-prefix', action='append', default=[],
                      help='additional package prefix to exclude from HW-APP-002 (repeatable)')
    scan.add_argument('--privileged-api-no-default-excludes', action='store_true',
                      help='include com.google* and com.android* packages in HW-APP-002 analysis')
    scan.add_argument('--blocked-certs', type=Path, help='JSON SHA-256 signing-certificate blocklist; requires app_extraction and --extract-apks')
    scan.add_argument('--package', action='append', default=[], help='restrict package analysis; repeatable')
    scan.add_argument('--max-apps', type=positive, help='optional package count cap; default no cap')
    scan.add_argument('--mobsf-url', help='explicitly upload extracted APKs to this MobSF URL')
    scan.add_argument('--mobsf', action='store_true', help='upload APKs from --mobsf-upload-dir to MobSF')
    scan.add_argument('--mobsf-upload-dir', type=Path, default=Path('mobsf-upload'),
                      help='folder of APKs for --mobsf (default: mobsf-upload)')
    scan.add_argument('--mobsf-poll-seconds', type=positive, default=5, help='MobSF queue/report polling interval (default 5 seconds)')
    scan.add_argument('--drozer', action='store_true', help='query a prepared Drozer agent')
    scan.add_argument('--drozer-bin', default='drozer', help='Drozer CLI executable')
    scan.add_argument('--drozer-server', default='127.0.0.1')
    scan.add_argument('--drozer-list-path', type=device_path, action='append', default=[], help='agent directory listing target; repeatable')
    scan.add_argument('--drozer-read-path', type=device_path, action='append', default=[], help='agent one-byte read test of a regular file; contents discarded')
    scan.add_argument('--drozer-readable-path', type=device_path, action='append', default=[], help='run scanner.misc.readablefiles on an agent-visible directory; repeatable')
    scan.add_argument('--drozer-write-dir', type=device_path, action='append', default=[], help='opt in to creating/writing/removing a unique probe file in this directory')
    scan.add_argument('--drozer-entry-limit', type=positive, default=50)
    scan.add_argument('--emba-firmware', type=Path, help='run EMBA against an existing local firmware image/directory')
    scan.add_argument('--emba', default='emba', help='path to EMBA executable')
    scan.add_argument('--integration-timeout', type=positive, default=1800)
    return p


def report(root, document):
    summarize(document)
    write_json(root / 'report.json', document)
    lines = ['Hexwarden - Android security audit', 'Run: ' + document['run_id'],
             'Device: ' + str(document.get('device')), 'Status: ' + document['status'],
             'Coverage status is not a security pass/fail.', '']
    summary = document['summary']
    lines.extend([f"Findings: {summary['findings']} | Classifications: {json.dumps(summary['by_classification'])}",
                  f"Automated analysis: {json.dumps(summary['analysis'])}",
                  summary['interpretation'], ''])
    if summary['requested_modules_not_started']:
        lines.append('NOT STARTED: ' + ', '.join(summary['requested_modules_not_started']))
    if document.get('error'):
        lines.append('Error: ' + document['error'])
    if document.get('capabilities'):
        device = document['capabilities']['device']
        lines.extend(['Preflight: capabilities.json',
                      f"  Android SDK: {device['sdk']}; shell UID: {device['shell_uid']}; root: {device['root']['status']}"])
    for result in document['modules']:
        lines.append(f"[{result['category']}/{result['module']}] {result['status']}")
        coverage = result['coverage']
        lines.append(f"  Collection: {coverage['collection']['status']} | Analysis: {coverage['analysis']['status']} | Manual verification: {'required' if coverage['manual_verification']['required'] else 'not flagged'}")
        for finding in result['findings']:
            lines.append(f"  {finding['severity'].upper()} [{finding['classification']}] {finding['rule_id']}: {finding['title']}")
            lines.append('    ID: ' + finding['id'] + ' | Asset: ' + json.dumps(finding['asset']))
            lines.append('    ' + json.dumps(finding['detail'], ensure_ascii=False))
            lines.append('    Action: ' + finding['remediation'])
            lines.append('    Verify: ' + finding['verification'])
            for ref in finding['evidence']:
                lines.append('    Evidence: ' + ref['path'] + (' ' + json.dumps(ref['locator']) if 'locator' in ref else ''))
        for check in result.get('analysis_checks', []):
            if check['status'] != 'evaluated':
                lines.append(f"  NOT EVALUATED: {check['check_id']} ({check.get('scope')}) {check.get('reason') or ''}")
        for limitation in result['limitations']:
            lines.append('  COVERAGE: ' + limitation)
        lines.append('')
    (root / 'report.txt').write_text('\n'.join(lines) + '\n')


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    if '--no-banner' not in arguments and '--version' not in arguments:
        print(BANNER, file=sys.stderr)
    p = parser()
    args = p.parse_args(arguments)
    modules = registry()
    if args.action == 'list':
        for name, module in modules.items():
            print(f'{module.CATEGORY:24} {name}')
        return 0
    if args.user < 0:
        p.error('--user must be nonnegative')
    if args.capture_snaplen < 0:
        p.error('--capture-snaplen must be zero or positive')
    for package in args.package:
        if not re.fullmatch(r'[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*', package):
            p.error('invalid package name')
    if args.modules:
        selected = list(args.modules)
    elif args.radamsa_fuzz and not args.category:
        # The explicit fuzz flag is a separate workflow; do not silently rerun
        # every collection module unless the caller asks for them.
        selected = ['radamsa_fuzz']
    else:
        selected = list(() if args.mobsf and not args.category else modules)
        if not args.radamsa_fuzz:
            selected = [name for name in selected if name != 'radamsa_fuzz']
    if args.radamsa_fuzz and 'radamsa_fuzz' not in selected:
        selected.append('radamsa_fuzz')
    if set(selected) - modules.keys():
        p.error('unknown modules: ' + ', '.join(sorted(set(selected) - modules.keys())))
    selected = list(dict.fromkeys(name for name in selected if not args.category or modules[name].CATEGORY in args.category))
    if args.radamsa_fuzz and 'radamsa_fuzz' not in selected:
        selected.append('radamsa_fuzz')
    if not selected and not args.mobsf:
        p.error('selection contains no modules')
    if 'radamsa_fuzz' in selected and not args.radamsa_fuzz:
        p.error('radamsa_fuzz requires --radamsa-fuzz')
    if args.radamsa_fuzz:
        if not args.radamsa_target:
            p.error('--radamsa-fuzz requires at least one --radamsa-target')
        if not args.radamsa_seed_file:
            p.error('--radamsa-fuzz requires --radamsa-seed-file')
        for path in args.radamsa_seed_file:
            if not path.is_file():
                p.error(f'Radamsa seed file does not exist or is not a file: {path}')
        if args.radamsa_count > 10000:
            p.error('--radamsa-count must not exceed 10000')
        if args.radamsa_max_payload > 1024 * 1024:
            p.error('--radamsa-max-payload must not exceed 1048576 bytes')
    args.signer_policy = None
    if args.blocked_certs:
        if not args.extract_apks or 'app_extraction' not in selected:
            p.error('--blocked-certs requires --extract-apks and app_extraction')
        from .app_trust import load_policy
        try:
            args.signer_policy = load_policy(args.blocked_certs)
        except (OSError, ValueError) as exc:
            p.error(f'invalid --blocked-certs policy: {exc}')
    if (args.drozer_list_path or args.drozer_read_path or args.drozer_write_dir or args.drozer_readable_path) and not args.drozer:
        p.error('Drozer filesystem options require --drozer')
    if args.drozer_entry_limit > 1000:
        p.error('--drozer-entry-limit must not exceed 1000')
    if args.bt_mac and 'bluetooth' not in selected:
        p.error('--bt-mac requires selecting the bluetooth module')
    if (args.bt_read or args.bt_pair or args.bt_connect_classic or args.bt_write_target or args.bt_write_payload or args.bt_fuzz) and not args.bt_mac:
        p.error('Bluetooth read/pair/connect options require --bt-mac')
    if (args.bt_read or args.bt_pair) and args.bt_mode == 'classic':
        p.error('--bt-read/--bt-pair require BLE mode')
    if args.bt_connect_classic and args.bt_mode == 'ble':
        p.error('--bt-connect-classic requires classic mode')
    if (args.bt_write_target or args.bt_write_payload or args.bt_fuzz) and args.bt_mode == 'classic':
        p.error('BLE write/fuzz options require BLE mode')
    if args.bt_write_payload and not args.bt_write_target:
        p.error('--bt-write-payload requires at least one --bt-write-target')
    if args.bt_fuzz and not args.bt_write_target:
        p.error('--bt-fuzz requires at least one --bt-write-target')
    if args.bt_write_target and not args.bt_write_payload and not args.bt_fuzz:
        p.error('--bt-write-target requires --bt-write-payload or --bt-fuzz')
    if args.bt_fuzz_count > 64:
        p.error('--bt-fuzz-count must not exceed 64')
    if args.mobsf_url and not args.mobsf:
        p.error('--mobsf-url requires --mobsf')
    if args.mobsf:
        if not args.mobsf_url:
            p.error('--mobsf requires --mobsf-url')
        if not args.mobsf_upload_dir.is_dir():
            p.error(f'MobSF upload directory does not exist or is not a directory: {args.mobsf_upload_dir}')
    if args.mobsf_url:
        parsed = urlparse(args.mobsf_url)
        if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            p.error('MobSF requires an HTTP(S) URL without credentials, query or fragment')
        if parsed.scheme == 'http' and parsed.hostname not in ('localhost', '127.0.0.1', '::1'):
            p.error('remote MobSF URLs must use HTTPS')
    if args.emba_firmware and not args.emba_firmware.exists():
        p.error('firmware path does not exist')
    os.umask(0o077)
    run_id = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid4().hex[:8]
    root = args.data_dir.resolve() / run_id
    root.mkdir(parents=True, mode=0o700)
    handler = logging.FileHandler(root / 'audit.log')
    handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    document = {'schema_version': 2, 'tool': {'name': 'Hexwarden', 'version': __version__},
                'run_id': run_id, 'started_at': datetime.now(timezone.utc).isoformat(),
                'device': args.serial, 'status': 'running', 'modules': [], 'requested_modules': selected,
                'scope': {'user': args.user, 'packages': args.package, 'root': args.root,
                          'extract_apks': args.extract_apks, 'capture_seconds': args.capture_seconds,
                          'capture_interface': args.capture_interface, 'capture_snaplen': args.capture_snaplen,
                          'patch_max_age': args.patch_max_age, 'max_apps': args.max_apps,
                          'mobsf': args.mobsf, 'mobsf_upload_dir': str(args.mobsf_upload_dir),
                          'radamsa_fuzz': args.radamsa_fuzz,
                          'radamsa_targets': args.radamsa_target,
                          'radamsa_protocol': args.radamsa_protocol,
                          'radamsa_seed_files': [str(path) for path in args.radamsa_seed_file],
                          'radamsa_count': args.radamsa_count,
                          'radamsa_timeout': args.radamsa_timeout,
                          'radamsa_max_seconds': args.radamsa_max_seconds,
                          'radamsa_monitor_crashes': not args.radamsa_no_crash_monitor,
                          'radamsa_delay_ms': args.radamsa_delay_ms,
                          'radamsa_max_payload': args.radamsa_max_payload,
                          'privileged_api_exclude_prefix': args.privileged_api_exclude_prefix,
                          'privileged_api_no_default_excludes': args.privileged_api_no_default_excludes}}
    document['scope']['bluetooth'] = {
        'mac': args.bt_mac, 'mode': args.bt_mode, 'timeout': args.bt_timeout,
        'read': args.bt_read, 'pair': args.bt_pair, 'connect_classic': args.bt_connect_classic,
        'write_targets': args.bt_write_target, 'write_payload_count': len(args.bt_write_payload),
        'fuzz': args.bt_fuzz, 'fuzz_count': args.bt_fuzz_count}
    document['scope']['drozer'] = {'enabled': args.drozer, 'server': args.drozer_server,
        'list_paths': args.drozer_list_path or ['/data', '/data/local/tmp', '/sdcard'],
        'read_paths': args.drozer_read_path, 'readable_paths': args.drozer_readable_path,
        'write_directories': args.drozer_write_dir,
        'entry_limit': args.drozer_entry_limit}
    exit_code = 0
    try:
        devices = subprocess.run([args.adb, 'devices'], capture_output=True, text=True, timeout=args.timeout)
        (root / 'adb-devices.txt').write_text(devices.stdout + devices.stderr)
        if devices.returncode:
            raise RuntimeError('adb devices failed; inspect adb-devices.txt')
        available = [parts[0] for line in devices.stdout.splitlines() if len(parts := line.split()) == 2 and parts[1] == 'device']
        if args.serial:
            if args.serial not in available:
                raise RuntimeError('Selected device is absent, offline or unauthorized')
        elif len(available) == 1:
            args.serial = available[0]
        else:
            raise RuntimeError('Connect one authorized device or select it using --serial')
        document['device'] = args.serial
        c = Context(args, root)
        document['capabilities'] = discover(c)
        report(root, document)
        for name in selected:
            result = c.start(name, modules[name].CATEGORY)
            document['modules'].append(result)
            try:
                modules[name].run(c)
            except Exception as exc:
                result['status'] = 'error'
                c.note(f'Module failed: {type(exc).__name__}: {exc}')
                logging.exception('Module %s failed', name)
            report(root, document)
        external(c, document['modules'])
        document['status'] = 'partial' if any(r['status'] != 'collected' for r in document['modules']) else 'collected'
        if any(r['status'] == 'error' for r in document['modules']):
            exit_code = 1
    except KeyboardInterrupt:
        document['status'] = 'interrupted'
        if document['modules']:
            document['modules'][-1]['interrupted'] = True
        exit_code = 130
    except Exception as exc:
        document['status'] = 'error'
        document['error'] = f'{type(exc).__name__}: {exc}'
        logging.error(document['error'])
        exit_code = 1
    finally:
        document['finished_at'] = datetime.now(timezone.utc).isoformat()
        report(root, document)
        logger.removeHandler(handler)
        handler.close()
        inventory(root)
    print(f'Reports and evidence: {root}')
    return exit_code
