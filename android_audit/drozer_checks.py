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
        c.check('drozer_agent_identity', False, reason='No identity event was returned.')
        c.note('Drozer agent identity not established; probe results cannot be attributed.')
        return
    c.result['execution_context'] = identity
    c.check('drozer_agent_identity', True)
    report_uids(c, events, identity)
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
    for event_index, event in enumerate(events):
        refs = [{**ref, 'locator': {'json_pointer': '/' + str(event_index)}} for ref in c.latest_evidence]
        if event['kind'] == 'package_grants':
            c.check('effective_package_grants', True, scope=event['package'], evidence=refs)
            grants = [p['permission'] for p in event['permissions']
                      if p.get('granted') is True and p['permission'] in SENSITIVE_GRANTS]
            if grants:
                c.finding('HW-DZ-001',
                          {'package': event['package'], 'uid': event['uid'], 'permissions': grants,
                           'observer': identity, 'appops_verified': False}, 'info', 'high', evidence=refs)
        elif event['kind'] == 'filesystem':
            c.check('agent_filesystem_probe', event.get('status') == 'success',
                    scope={'path': event['path'], 'action': event['action']}, evidence=refs,
                    reason='Access could not be established.' if event.get('status') != 'success' else None)
            if event.get('cleanup_succeeded'):
                cleaned.add(event['probe_path'])
            if event.get('status') == 'success':
                # Directory names and content bytes stay outside finding text.
                c.finding('HW-DZ-002',
                          {'path': event['path'], 'action': event['action'], 'agent': identity,
                           'bytes_read': event.get('bytes_read'), 'bytes_written': event.get('bytes_written')},
                          'info', 'high', asset={'device': getattr(c.args, 'serial', None), 'path': event['path'], 'action': event['action'], 'agent_uid': identity.get('uid'), 'agent_package': identity.get('package')}, evidence=refs)
            else:
                c.note(f"Drozer {event.get('action')} probe for {event.get('path')}: {event.get('status')}; denial, invisibility or I/O error is not proof of globally secure ACLs.")
            if event.get('truncated'):
                c.note(f"Directory listing capped: {event['path']}.")
        elif event['kind'] == 'error':
            c.note(f"Drozer {event.get('stage')} failed: {event.get('error')}")
    for path in sorted(created - cleaned):
        c.finding('HW-DZ-003', {'path': path, 'agent': identity}, 'low', 'high')
        c.note('A probe file may remain after failure/interruption; inspect the recorded path and remove it manually.')


def report_uids(c, events, identity):
    groups = {}
    for index, event in enumerate(events):
        if event['kind'] != 'package_uid' or type(event.get('uid')) is not int or event['uid'] < 0:
            continue
        uid = event['uid']
        group = groups.setdefault(uid, {'uid': uid, 'user_id': uid // 100000, 'app_id': uid % 100000,
            'packages': set(), 'privileged_candidates': set(), 'sensitive_grants': set(), 'evidence': []})
        group['packages'].update(event.get('shared_packages', []))
        group['packages'].add(event['package'])
        if event.get('privileged_candidate'):
            group['privileged_candidates'].add(event['package'])
        group['evidence'].extend({**ref, 'locator': {'json_pointer': '/' + str(index)}} for ref in c.latest_evidence)
    for event in events:
        if event['kind'] == 'package_grants' and event.get('uid') in groups:
            groups[event['uid']]['sensitive_grants'].update(p['permission'] for p in event['permissions']
                if p.get('granted') is True and p['permission'] in SENSITIVE_GRANTS)
    rows = []
    for uid, group in sorted(groups.items()):
        for key in ('packages', 'privileged_candidates', 'sensitive_grants'):
            group[key] = sorted(group[key])
        group['shared'] = len(group['packages']) > 1
        group['system_uid_candidate'] = group['app_id'] < 10000
        rows.append(group)
        if group['shared'] or group['system_uid_candidate']:
            elevated = group['system_uid_candidate'] or group['privileged_candidates'] or group['sensitive_grants']
            c.finding('HW-DZ-004', group, 'medium' if elevated else 'info', 'high',
                      asset={'device': getattr(c.args, 'serial', None), 'agent_package': identity.get('package'), 'uid': uid},
                      evidence=group['evidence'])
    complete = any(e['kind'] == 'uid_inventory_complete' for e in events)
    c.check('drozer_package_uids', complete and bool(rows),
            reason=None if complete and rows else 'UID inventory missing, empty or interrupted.')
    path = c.directory / 'shared-uids.json'
    write_json(path, rows)
    c.result['evidence'].append({'path': str(path.relative_to(c.root)), 'kind': 'derived'})
    c.note('UID groups describe PackageManager identities visible to the Drozer agent, not observed running processes. '
           'Full UIDs keep Android users separate. Package filters select starting packages; visible same-UID peers '
           'are included. System UID range, priv-app paths and sensitive grants prioritize review, not proof of root '
           'or identical SELinux/API access. Package visibility can hide peers.')


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
    # These inventory modules are global when invoked without package arguments.
    # Keep the complete package/component surface in one pass instead of reducing
    # it to a selected-package attack-surface summary.
    module('app.package.info')
    module('app.package.shareduid')
    for name in ('app.activity.info', 'app.service.info', 'app.provider.info', 'app.broadcast.info'):
        module(name)
    packages = c.args.package[:c.args.max_apps] if c.args.max_apps else c.args.package
    if len(packages) < len(c.args.package):
        c.note(f'Drozer package inspection capped at {c.args.max_apps} packages.')
    if not packages:
        c.note('Per-package Drozer grant and AppOps checks require explicit --package selections; global inventory still runs.')
    for package in packages:
        c.shell(f'cmd appops get --user {c.args.user} ' + shlex.quote(package), 'appops_' + package)
    args = ['--entry-limit', str(c.args.drozer_entry_limit)]
    if c.args.max_apps:
        args.extend(['--uid-limit', str(c.args.max_apps)])
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
    c.latest_evidence = [{'path': str(path.relative_to(c.root))}]
    analyze(c, events)
    # Special accesses have AppOps/policy semantics beyond PackageManager grants.
    for key in ('enabled_accessibility_services', 'enabled_notification_listeners'):
        c.setting('secure', key)
    c.shell('dumpsys device_policy', 'special_access_policy')
    c.note('All Drozer operations use its CLI and the connected agent identity. Global package/component inventory and app.package.shareduid run without a package argument; PackageManager grants and AppOps remain scoped to selected packages. Grants do not establish AppOps authorization or successful privileged API use. Inventory is not invocation. ADB policy evidence is separate from agent tests. Confirm the Drozer endpoint matches the ADB target; no automatic forwarding, agent installation or privilege escalation occurs.')
