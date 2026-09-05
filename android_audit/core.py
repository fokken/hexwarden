from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shlex
import signal
import subprocess
import time
from pathlib import Path
from .findings import RULES, instance_id

ERROR = re.compile(r'permission denied|not found|unknown command|can.t find service|SecurityException|not permitted|inaccessible', re.I)
STDOUT_ERROR = re.compile(r'^(?:/system/bin/sh:.*|sh:.*|error:.*|exception.*|java\.lang\..*|permission denied.*|.*: permission denied|can.t find service.*|unknown command.*)$', re.I | re.M)


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n')


def execute(argv, timeout, output, cwd=None):
    """Spool stdout/stderr to disk rather than holding unbounded captures in RAM."""
    start = time.monotonic()
    stderr = output.with_suffix(output.suffix + '.stderr')
    timed_out = False
    with output.open('wb') as out, stderr.open('wb') as err:
        try:
            proc = subprocess.Popen(argv, stdout=out, stderr=err, cwd=cwd, stdin=subprocess.DEVNULL,
                                    start_new_session=os.name == 'posix')
            try:
                code = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                if os.name == 'posix':
                    os.killpg(proc.pid, signal.SIGKILL)
                else:
                    proc.kill()
                code = proc.wait()
            except KeyboardInterrupt:
                if os.name == 'posix':
                    os.killpg(proc.pid, signal.SIGKILL)
                else:
                    proc.kill()
                proc.wait()
                raise
        except OSError as exc:
            err.write(str(exc).encode())
            code = 127
    return {'argv': argv, 'returncode': code, 'timed_out': timed_out,
            'duration_seconds': round(time.monotonic() - start, 3)}


class Context:
    def __init__(self, args, root):
        self.args, self.root = args, root
        self.cache = {}
        self.result = None
        self.counter = 0
        self.capabilities = None
        self.latest_evidence = []

    def start(self, name, category):
        self.result = dict(module=name, category=category, status='collected', findings=[],
                           limitations=[], evidence=[], analysis_checks=[])
        self.latest_evidence = []
        self.directory = self.root / 'evidence' / name
        self.directory.mkdir(parents=True)
        return self.result

    def note(self, message):
        self.result['limitations'].append(message)
        if self.result['status'] == 'collected':
            self.result['status'] = 'partial'

    def evidence_for(self, *labels):
        return [{'path': e['path']} for e in self.result['evidence'] if e.get('label') in labels]

    def check(self, name, evaluated, *, scope=None, evidence=None, reason=None):
        self.result['analysis_checks'].append({'check_id': name,
            'status': 'evaluated' if evaluated else 'not_evaluated',
            'scope': scope, 'reason': reason if evaluated or reason else 'Required input unavailable or could not be interpreted reliably.',
            'evidence': list(self.latest_evidence if evidence is None else evidence)})

    def finding(self, rule_id, detail, severity='info', confidence='medium', *, asset=None, evidence=None):
        rule = RULES[rule_id]
        if asset is None:
            asset = {'device': getattr(self.args, 'serial', None), 'user': getattr(self.args, 'user', None)}
            if isinstance(detail, dict):
                asset.update({k: detail[k] for k in ('package', 'path', 'mac', 'protocol', 'endpoint',
                    'service_uuid', 'characteristic_uuid', 'handle', 'store', 'name', 'action') if k in detail})
        refs = list(self.latest_evidence if evidence is None else evidence)
        finding = dict(rule, id=instance_id(rule_id, asset), asset=asset, detail=detail,
                       severity=severity, confidence=confidence, evidence=refs,
                       verification_status='pending' if rule['classification'] == 'review_candidate' else 'observed')
        for existing in self.result['findings']:
            if existing['id'] == finding['id']:
                for ref in refs:
                    if ref not in existing['evidence']:
                        existing['evidence'].append(ref)
                if detail != existing['detail']:
                    observations = existing.setdefault('additional_observations', [])
                    if detail not in observations:
                        observations.append(detail)
                return
        self.result['findings'].append(finding)

    def skip(self, command, label, reason):
        self.latest_evidence = []
        self.result.setdefault('skipped_checks', []).append(
            {'label': label, 'command': command, 'reason': reason, 'capability_evidence': 'capabilities.json'})
        self.note(f'{label}: skipped: {reason}')

    def command(self, argv, label='command', timeout=None, binary=False, cwd=None):
        self.latest_evidence = []
        if self.capabilities:
            tool = self.capabilities['host_tools'].get(argv[0], {})
            if tool.get('status') == 'unavailable':
                self.skip(argv, label, f'Host executable {argv[0]} unavailable in preflight.')
                return None
        self.counter += 1
        suffix = 'pcap' if binary and label == 'traffic' else 'bin' if binary else 'txt'
        path = self.directory / f'{self.counter:04d}-{label}.{suffix}'
        meta = execute(argv, timeout or self.args.timeout, path, cwd=cwd)
        if cwd is not None:
            meta['cwd'] = str(cwd)
        meta['path'] = str(path.relative_to(self.root))
        meta['label'] = label
        meta['stderr_path'] = str(path.with_suffix(path.suffix + '.stderr').relative_to(self.root))
        with path.open('rb') as stream:
            sample = stream.read(2 * 1024 * 1024)
        err = path.with_suffix(path.suffix + '.stderr').read_text(errors='replace')[:10000]
        value = '' if binary else sample.decode(errors='replace')
        meta['analysis_truncated'] = not binary and path.stat().st_size > len(sample)
        meta['ok'] = meta['returncode'] == 0 and not meta['timed_out'] and not ERROR.search(err) and not STDOUT_ERROR.search(value)
        self.result['evidence'].append(meta)
        self.latest_evidence = [{'path': meta['path']}]
        if not meta['ok']:
            self.note(f'{label}: command failed, denied, unavailable, or timed out; inspect evidence.')
        if meta['analysis_truncated']:
            self.note(f'{label}: automated analysis limited to first 2 MiB; full output retained.')
        logging.info('%s: %s (%s)', self.result['module'], label, 'ok' if meta['ok'] else 'incomplete')
        return value if meta['ok'] else None

    def shell(self, command, label='shell', root=False, timeout=None, binary=False):
        if root and not self.args.root:
            self.skip(command, label, 'Requires --root and existing privileges.')
            return None
        use_su = root
        if self.capabilities:
            device = self.capabilities['device']
            if root and device['root']['status'] != 'available':
                self.skip(command, label, 'Preflight could not establish requested root access.')
                return None
            use_su = root and device['root']['method'] == 'su'
            commands = device['root']['commands'] if root else device['commands']
            parts = shlex.split(command)
            executable = parts[0] if parts else ''
            required = [executable]
            if executable == 'timeout' and 'tcpdump' in parts:
                required.append('tcpdump')
            for dependency in required:
                if commands.get(dependency) == 'unavailable':
                    self.skip(command, label, f'Device command {dependency} absent in {"root" if root else "ADB shell"} PATH.')
                    return None
            services = device['services']
            if not root and executable == 'dumpsys' and len(parts) > 1 and not parts[1].startswith('-'):
                if services['status'] == 'collected' and parts[1] not in services['names']:
                    self.skip(command, label, f'Android service {parts[1]} absent from preflight dumpsys inventory.')
                    return None
        remote = 'su -c ' + shlex.quote(command) if use_su else command
        return self.command([self.args.adb, '-s', self.args.serial,
                             'exec-out' if binary else 'shell', remote], label, timeout, binary)

    def prop(self, key):
        value = self.shell('getprop ' + shlex.quote(key), key)
        if value is not None and value.strip() not in ('', 'null'):
            return value.strip()
        self.note(f'{key}: property unavailable.')
        return None

    def setting(self, namespace, key):
        value = self.shell(f'settings --user {self.args.user} get {namespace} {key}', key)
        if value is not None and value.strip() not in ('', 'null'):
            return value.strip()
        self.note(f'{key}: setting unavailable for user {self.args.user}.')
        return None

    def packages(self):
        value = self.shell('pm list packages -f', 'packages') or ''
        packages = []
        for line in value.splitlines():
            if line.startswith('package:') and '=' in line:
                path, package = line[8:].rsplit('=', 1)
                if re.fullmatch(r'[A-Za-z0-9_.]+', package):
                    packages.append((package, path))
        if self.args.package:
            packages = [p for p in packages if p[0] in self.args.package]
        packages.sort(key=lambda p: ('/priv-app/' not in p[1], p[0]))
        if self.args.max_apps and len(packages) > self.args.max_apps:
            self.note(f'App collection capped at {self.args.max_apps} packages.')
            packages = packages[:self.args.max_apps]
        return packages


def inventory(root):
    entries = []
    for path in sorted(root.rglob('*')):
        if path.is_file() and path.name != 'inventory.json':
            digest = hashlib.sha256()
            with path.open('rb') as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b''):
                    digest.update(block)
            entries.append(dict(path=str(path.relative_to(root)), size=path.stat().st_size,
                                sha256=digest.hexdigest()))
    write_json(root / 'inventory.json', entries)
