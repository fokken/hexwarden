"""CLI-only Drozer orchestration and agent-context evidence analysis."""
import configparser
import json
from pathlib import Path
import re
import shlex
import shutil
from .core import write_json

SENSITIVE_GRANTS = {
    'android.permission.INSTALL_PACKAGES', 'android.permission.DELETE_PACKAGES',
    'android.permission.WRITE_SECURE_SETTINGS', 'android.permission.READ_LOGS',
    'android.permission.MANAGE_EXTERNAL_STORAGE', 'android.permission.INTERACT_ACROSS_USERS',
    'android.permission.INTERACT_ACROSS_USERS_FULL', 'android.permission.DUMP',
    'android.permission.READ_PRIVILEGED_PHONE_STATE', 'android.permission.MASTER_CLEAR',
}


def parse_events(text):
    events = []
    for line in text.splitlines():
        if line.startswith('HEXWARDEN_JSON '):
            try:
                item = json.loads(line[len('HEXWARDEN_JSON '):])
                if isinstance(item, dict) and isinstance(item.get('kind'), str):
                    events.append(item)
            except ValueError:
                continue
    return events


def analyze(c, events):
    identity = next((e for e in events if e['kind'] == 'identity'), None)
    if identity is None:
        c.note('Drozer agent identity not established; probe results cannot be attributed.')
        return
    c.result['execution_context'] = identity
    if identity.get('user_id') is not None and identity['user_id'] != c.args.user:
        c.note('Drozer agent user differs from the selected ADB settings user; do not merge their access results.')
    if identity.get('uid') in (0, 1000, 2000):
        c.note('Agent UID is privileged or shell; results do not represent an ordinary app sandbox.')
    if not identity.get('selinux_context'):
        c.note('Agent SELinux context unavailable.')
    if not any(e['kind'] == 'complete' for e in events):
        c.note('Drozer probe did not finish; some requested checks may not have run.')
    created = {e['path'] for e in events if e['kind'] == 'probe_created'}
    cleaned = set()
    for event in events:
        if event['kind'] == 'package_grants':
            grants = [p['permission'] for p in event['permissions']
                      if p.get('granted') is True and p['permission'] in SENSITIVE_GRANTS]
            if grants:
                c.finding('Sensitive package permissions granted',
                          {'package': event['package'], 'uid': event['uid'], 'permissions': grants,
                           'observer': identity, 'appops_verified': False}, 'info', 'high')
        elif event['kind'] == 'filesystem':
            if event.get('cleanup_succeeded'):
                cleaned.add(event['probe_path'])
            if event.get('status') == 'success':
                # Directory names and content bytes stay outside finding text.
                c.finding('Filesystem access succeeded from Drozer agent',
                          {'path': event['path'], 'action': event['action'], 'agent': identity,
                           'bytes_read': event.get('bytes_read'), 'bytes_written': event.get('bytes_written')},
                          'info', 'high')
            else:
                c.note(f"Drozer {event.get('action')} probe for {event.get('path')}: {event.get('status')}; denial, invisibility or I/O error is not proof of globally secure ACLs.")
            if event.get('truncated'):
                c.note(f"Directory listing capped: {event['path']}.")
        elif event['kind'] == 'error':
            c.note(f"Drozer {event.get('stage')} failed: {event.get('error')}")
    for path in sorted(created - cleaned):
        c.finding('Drozer write probe cleanup not confirmed', {'path': path, 'agent': identity}, 'low', 'high')
        c.note('A probe file may remain after failure/interruption; inspect the recorded path and remove it manually.')


def run(c):
    executable = shutil.which(c.args.drozer_bin)
    if not executable:
        c.result['status'] = 'skipped'
        c.note(f'Drozer CLI unavailable: {c.args.drozer_bin}.')
        return
    workspace = c.root / 'integrations' / 'drozer'
    repo = workspace / 'repository'
    repo.mkdir(parents=True)
    for name in ('__init__.py', '.drozer_repository'):
        (repo / name).write_text('')
    shutil.copyfile(Path(__file__).parent / 'drozer_modules' / 'audit.py', repo / 'hexwarden_probe.py')
    config = configparser.ConfigParser()
    config['repositories'] = {'hexwarden': str(repo).replace('%', '%%')}
    with (workspace / '.drozer_config').open('w') as stream:
        config.write(stream)
    help_text = c.command([executable, 'console', 'connect', '--help'], 'drozer_cli_help') or ''
    base = [executable, 'console', 'connect', '--server', c.args.drozer_server]
    for flag in ('--no-color', '--no-password'):
        if flag in help_text:
            base.append(flag)

    def invoke(command, label):
        return c.command([*base, '-c', command], label, c.args.integration_timeout, cwd=workspace)

    listing = invoke('list', 'drozer_available_modules')
    if listing is None:
        c.note('Drozer session/module discovery failed; remaining Drozer checks skipped.')
        return
    available = set(re.findall(r'^\s*((?:[a-z_]+\.)+[a-z_]+)\s', listing, re.M))
    write_json(workspace / 'capabilities.json', {'cli': executable, 'modules': sorted(available),
                                               'server': c.args.drozer_server})
    if not available:
        c.note('No supported Drozer modules recognized; remaining checks skipped.')
        return

    def module(name, args=()):
        if name not in available:
            c.note(f'Drozer module {name} unavailable to this agent/session.')
            return None
        return invoke(shlex.join(['run', name, *args]), name.replace('.', '_'))

    module('app.package.list')
    packages = c.args.package[:c.args.max_apps] if c.args.max_apps else c.args.package
    if len(packages) < len(c.args.package):
        c.note(f'Drozer package inspection capped at {c.args.max_apps} packages.')
    if not packages:
        c.note('Per-app Drozer inspection requires explicit --package selections; agent grants are still checked.')
    for package in packages:
        module('app.package.info', ['-a', package])
        module('app.package.attacksurface', [package])
        for name in ('app.activity.info', 'app.service.info', 'app.provider.info', 'app.broadcast.info'):
            module(name, ['-a', package])
        c.shell(f'cmd appops get --user {c.args.user} ' + shlex.quote(package), 'appops_' + package)
    args = ['--entry-limit', str(c.args.drozer_entry_limit)]
    for flag, values in (('--package', packages), ('--list-path', c.args.drozer_list_path or ['/data', '/data/local/tmp', '/sdcard']),
                         ('--read-path', c.args.drozer_read_path), ('--write-dir', c.args.drozer_write_dir)):
        for value in values:
            args.extend([flag, value])
    value = module('hexwarden.audit', args)
    if value is None and c.result['evidence']:
        # A timeout or failed command can still contain completed probe records.
        last = c.result['evidence'][-1]
        value = (c.root / last['path']).read_text(errors='replace')[:2 * 1024 * 1024]
    events = parse_events(value or '')
    path = workspace / 'agent-checks.json'
    write_json(path, events)
    c.result['evidence'].append({'path': str(path.relative_to(c.root)), 'kind': 'derived'})
    analyze(c, events)
    # Special accesses have AppOps/policy semantics beyond PackageManager grants.
    for key in ('enabled_accessibility_services', 'enabled_notification_listeners'):
        c.setting('secure', key)
    c.shell('dumpsys device_policy', 'special_access_policy')
    c.note('All Drozer operations use its CLI and the connected agent identity. PackageManager grants do not establish AppOps access or successful privileged API use. Package/component info is inventory, not invocation. ADB policy evidence is separate from agent tests. Confirm the Drozer endpoint matches the ADB target; no automatic forwarding, agent installation or privilege escalation occurs.')
