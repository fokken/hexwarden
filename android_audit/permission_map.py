"""Cross-package manifest permission relationships, not runtime grants."""
from .core import write_json
from .apps import manifest_evidence


def correlate(apps):
    permissions = {}
    def entry(name):
        return permissions.setdefault(name, {'permission': name, 'declarations': [], 'requesters': [], 'protected_components': []})
    for app in apps:
        for manifest in app['manifests']:
            origin = {'package': app['package'], 'apk': manifest['apk'],
                      'privileged_candidate': app.get('privileged_candidate', False)}
            for declaration in manifest['permissions']:
                if declaration['name']:
                    entry(declaration['name'])['declarations'].append({**origin, **declaration})
            for request in manifest.get('requested_permissions', []):
                if request['name']:
                    entry(request['name'])['requesters'].append({**origin, **request})
            for component in manifest['components']:
                guards = [(key, component.get(key)) for key in ('permission', 'read_permission', 'write_permission')]
                for index, rule in enumerate(component.get('path_permission_rules', [])):
                    guards.extend((f'path[{index}].{key}', rule.get(key)) for key in ('permission', 'readPermission', 'writePermission'))
                for guard, name in guards:
                    if name:
                        entry(name)['protected_components'].append({**origin, 'component': component['name'],
                            'type': component['type'], 'exported': component['exported'],
                            'enabled': component['enabled'], 'guard': guard})
    for row in permissions.values():
        owners = sorted({x['package'] for x in row['declarations']})
        row['declaring_packages'] = owners
        row['declaration_status'] = 'multiple_declarers' if len(owners) > 1 else 'observed' if owners else 'not_observed_in_scope'
        row['weak_exported_guards'] = bool(any(x['weak'] for x in row['declarations']) and
            any(x['exported'] is True and x['enabled'] for x in row['protected_components']))
    return [permissions[name] for name in sorted(permissions)]


def report_permissions(c, apps):
    rows = correlate(apps)
    path = c.directory / 'permission-correlation.json'
    write_json(path, rows)
    ref = {'path': str(path.relative_to(c.root)), 'kind': 'derived'}
    c.result['evidence'].append(ref)
    for row in rows:
        if row['weak_exported_guards'] or row['declaration_status'] == 'multiple_declarers':
            packages = set(row['declaring_packages']) | {x['package'] for x in row['protected_components']}
            refs = [ref] + [item for app in apps if app['package'] in packages
                            for manifest in app['manifests'] for item in manifest_evidence(manifest)]
            c.finding('HW-APP-010', row, 'medium',
                      asset={'device': c.args.serial, 'permission': row['permission']}, evidence=refs)
    c.note('Permission correlation covers decoded manifests within the selected package scope. '
           'Declarations identify candidate owners, not the effective PackageManager owner. '
           'Requests are not grants; SDK conditions, runtime checks, AppOps, signature/privileged exceptions '
           'and split merging require runtime verification, including through Drozer. '
           'A missing declaration in this scope is not a vulnerability.')
