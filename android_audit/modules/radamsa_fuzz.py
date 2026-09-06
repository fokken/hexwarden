"""Opt-in Radamsa fuzzing for user-selected TCP/UDP endpoints."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import logging
import os
from pathlib import Path
import socket
import subprocess
import signal
import time

from ..core import write_json

CATEGORY = 'networking'

CRASH_MARKERS = (
    'FATAL EXCEPTION', 'Fatal signal', 'SIGABRT', 'SIGSEGV', 'SIGBUS',
    'Abort message', 'ANR in ', 'am_crash', 'has died', 'tombstone',
)


def parse_target(value):
    """Parse an IPv4/IPv6 target written as HOST:PORT or [IPv6]:PORT."""
    if value.startswith('['):
        closing = value.find(']')
        if closing < 0 or closing + 1 >= len(value) or value[closing + 1] != ':':
            raise ValueError('expected [IPv6]:PORT')
        host, port_text = value[1:closing], value[closing + 2:]
    else:
        if ':' not in value:
            raise ValueError('expected IP:PORT or [IPv6]:PORT')
        host, port_text = value.rsplit(':', 1)
    try:
        ipaddress.ip_address(host)
        port = int(port_text)
    except (ValueError, TypeError) as exc:
        raise ValueError('target must contain a literal IP address and numeric port') from exc
    if not 1 <= port <= 65535:
        raise ValueError('port must be between 1 and 65535')
    return host, port


def _timestamp():
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds')


def _append_jsonl(path, record):
    with path.open('a', encoding='utf-8') as stream:
        stream.write(json.dumps(record, ensure_ascii=False) + '\n')
        stream.flush()
        # Keep the pre-send record durable enough to correlate a target crash.
        stream.flush()
        os.fsync(stream.fileno())


def _radamsa(radamsa, seed, timeout, max_payload):
    completed = subprocess.run([radamsa, '-n', '1'], input=seed, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=timeout, check=False)
    if completed.returncode:
        raise RuntimeError(completed.stderr.decode(errors='replace')[:500] or
                           f'radamsa exited with {completed.returncode}')
    payload = completed.stdout
    truncated = len(payload) > max_payload
    return payload[:max_payload], truncated


def _send(protocol, host, port, payload, timeout):
    family = socket.AF_INET6 if ':' in host else socket.AF_INET
    kind = socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM
    started = time.monotonic()
    response_length = None
    try:
        with socket.socket(family, kind) as connection:
            connection.settimeout(timeout)
            if protocol == 'tcp':
                connection.connect((host, port))
                connection.sendall(payload)
                try:
                    response_length = len(connection.recv(4096))
                except socket.timeout:
                    pass
            else:
                connection.sendto(payload, (host, port))
                try:
                    response_length = len(connection.recvfrom(4096)[0])
                except socket.timeout:
                    pass
        return {'status': 'sent', 'response_length': response_length,
                'duration_ms': round((time.monotonic() - started) * 1000, 1)}
    except OSError as exc:
        return {'status': 'error', 'error_type': type(exc).__name__, 'error': str(exc),
                'duration_ms': round((time.monotonic() - started) * 1000, 1)}


def _start_crash_monitor(c):
    """Start a bounded warning-level logcat stream before fuzzing begins."""
    output = c.directory / 'crash-monitor.log'
    error = c.directory / 'crash-monitor.log.stderr'
    command = [c.args.adb, '-s', c.args.serial, 'exec-out', 'logcat', '-v', 'threadtime', '*:W']
    stream = output.open('wb')
    err_stream = error.open('wb')
    try:
        process = subprocess.Popen(command, stdout=stream, stderr=err_stream,
                                   stdin=subprocess.DEVNULL, start_new_session=os.name == 'posix')
    except OSError:
        stream.close()
        err_stream.close()
        raise
    return {'process': process, 'output': output, 'error': error,
            'stream': stream, 'err_stream': err_stream, 'command': command}


def _stop_crash_monitor(monitor):
    process = monitor['process']
    try:
        if process.poll() is None:
            if os.name == 'posix':
                os.killpg(process.pid, signal.SIGTERM)
            else:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                if os.name == 'posix':
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
                process.wait(timeout=5)
    finally:
        monitor['stream'].close()
        monitor['err_stream'].close()


def _crash_matches(*paths):
    matches = []
    for path in paths:
        try:
            text = path.read_text(errors='replace')[-4 * 1024 * 1024:]
        except OSError:
            continue
        for line in text.splitlines():
            if any(marker.lower() in line.lower() for marker in CRASH_MARKERS):
                matches.append({'path': str(path), 'line': line[:1000]})
    return matches


def run(c):
    if not getattr(c.args, 'radamsa_fuzz', False):
        c.note('Radamsa fuzzing is disabled; use --radamsa-fuzz with explicit targets.')
        return
    tool = (c.capabilities or {}).get('host_tools', {}).get('radamsa', {})
    radamsa = tool.get('path')
    if not radamsa:
        c.skip(['radamsa'], 'radamsa', 'Radamsa is not available on the test machine.')
        c.check('radamsa_available', False, scope='host')
        return
    c.check('radamsa_available', True, scope='host')

    seed_paths = [Path(path) for path in c.args.radamsa_seed_file]
    seeds = []
    for path in seed_paths:
        try:
            data = path.read_bytes()
        except OSError as exc:
            c.note(f'Seed file {path}: {type(exc).__name__}: {exc}')
            continue
        if not data:
            c.note(f'Seed file {path} is empty; skipped.')
            continue
        seeds.append((path, data))
    if not seeds:
        c.check('radamsa_seed_inventory', False, scope='host')
        return
    c.check('radamsa_seed_inventory', True, scope=[str(path) for path, _ in seeds])

    targets = []
    for value in c.args.radamsa_target:
        try:
            targets.append((value, *parse_target(value)))
        except ValueError as exc:
            c.note(f'Invalid Radamsa target {value}: {exc}')
    if not targets:
        c.check('radamsa_target_selection', False, scope='host')
        return
    c.check('radamsa_target_selection', True, scope=[target[0] for target in targets])

    journal = c.directory / 'radamsa-fuzz.jsonl'
    monitor = None
    monitor_refs = []
    if getattr(c.args, 'radamsa_monitor_crashes', True):
        try:
            monitor = _start_crash_monitor(c)
            monitor_refs = [{'path': str(monitor['output'].relative_to(c.root)), 'kind': 'crash-monitor'},
                            {'path': str(monitor['error'].relative_to(c.root)), 'kind': 'crash-monitor-stderr'}]
            c.result['evidence'].extend(monitor_refs)
        except OSError as exc:
            c.note(f'Unable to start ADB crash monitor: {type(exc).__name__}: {exc}')
    else:
        c.note('ADB crash monitoring was disabled with --radamsa-no-crash-monitor.')
    summary = {'protocol': c.args.radamsa_protocol, 'targets': [item[0] for item in targets],
               'seed_files': [str(path) for path, _ in seeds], 'attempts': 0,
               'sent': 0, 'errors': 0, 'crash_monitor': bool(monitor)}
    limit = c.args.radamsa_count
    started = time.monotonic()
    try:
        for sequence in range(limit):
            seed_path, seed = seeds[sequence % len(seeds)]
            for target_text, host, port in targets:
                if time.monotonic() - started >= c.args.radamsa_max_seconds:
                    _append_jsonl(journal, {'timestamp': _timestamp(), 'status': 'campaign_timeout',
                                            'max_seconds': c.args.radamsa_max_seconds})
                    c.note('Radamsa campaign stopped at its maximum duration.')
                    break
                sequence_id = summary['attempts'] + 1
                try:
                    payload, truncated = _radamsa(radamsa, seed, c.args.radamsa_timeout,
                                                  c.args.radamsa_max_payload)
                except Exception as exc:
                    summary['errors'] += 1
                    record = {'sequence': sequence_id, 'timestamp': _timestamp(), 'target': target_text,
                              'protocol': c.args.radamsa_protocol, 'seed_file': str(seed_path),
                              'status': 'generation_error', 'error_type': type(exc).__name__, 'error': str(exc)}
                    _append_jsonl(journal, record)
                    summary['attempts'] += 1
                    continue
                record = {'sequence': sequence_id, 'timestamp': _timestamp(), 'target': target_text,
                          'protocol': c.args.radamsa_protocol, 'seed_file': str(seed_path),
                          'payload_hex': payload.hex(), 'payload_length': len(payload),
                          'payload_sha256': hashlib.sha256(payload).hexdigest(),
                          'payload_truncated': truncated, 'status': 'prepared'}
                _append_jsonl(journal, record)
                outcome = _send(c.args.radamsa_protocol, host, port, payload, c.args.radamsa_timeout)
                record.update(outcome, completed_timestamp=_timestamp())
                _append_jsonl(journal, record)
                summary['attempts'] += 1
                if outcome['status'] == 'sent':
                    summary['sent'] += 1
                else:
                    summary['errors'] += 1
                logging.info('Radamsa probe target=%s protocol=%s sequence=%s payload=%s status=%s',
                             target_text, c.args.radamsa_protocol, sequence_id, payload.hex(), outcome['status'])
                if c.args.radamsa_delay_ms:
                    time.sleep(c.args.radamsa_delay_ms / 1000)
            else:
                continue
            break
    finally:
        if monitor:
            _stop_crash_monitor(monitor)
            crash_buffer = c.shell('logcat -d -b crash -v threadtime', 'radamsa_crash_buffer')
            if crash_buffer is None:
                c.note('Device crash-buffer collection was unavailable; inspect the host crash monitor.')
            matches = _crash_matches(monitor['output'])
            if crash_buffer:
                crash_path = c.directory / 'crash-buffer.txt'
                crash_path.write_text(crash_buffer)
                c.result['evidence'].append({'path': str(crash_path.relative_to(c.root)), 'kind': 'crash-buffer'})
                matches.extend(_crash_matches(crash_path))
            summary['crash_indicators'] = matches
            if matches:
                c.note(f'Detected {len(matches)} crash/ANR indicator lines; correlate them with payload timestamps.')
    write_json(c.directory / 'summary.json', summary)
    c.result['evidence'].append({'path': str(journal.relative_to(c.root)), 'kind': 'payload-journal'})
    c.result['evidence'].append({'path': str((c.directory / 'summary.json').relative_to(c.root)), 'kind': 'summary'})
    c.check('radamsa_fuzz_campaign', summary['attempts'] > 0, scope=summary['targets'])
    if summary['errors']:
        c.note(f"Radamsa campaign completed with {summary['errors']} errors; inspect the timestamped payload journal.")
