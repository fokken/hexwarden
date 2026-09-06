from ..apps import collect_apps, record_manifest_checks, manifest_evidence
from ..permission_map import report_permissions
from .privileged_apis import excluded_prefixes
CATEGORY = 'running_applications'

def run(c):
    c.shell('pm list permissions -f', 'permissions')
    apps = collect_apps(c)
    record_manifest_checks(c, apps, 'custom_permissions')
    report_permissions(c, apps)
    prefixes = excluded_prefixes(c)
    excluded = 0
    for app in apps:
        if any(app['package'].startswith(prefix) for prefix in prefixes):
            excluded += 1
            continue
        for manifest in app['manifests']:
            for permission in manifest['permissions']:
                if permission['weak']:
                    c.finding('HW-APP-003',
                              {'package': app['package'], **permission}, 'medium', evidence=manifest_evidence(manifest, permission=permission['name']))
    c.note('Normal/dangerous protection is a review candidate, not proof of abuse. Resolve permission ownership, consumers, install order and signature/privileged allowlists.')
    c.note(f'HW-APP-003 package filter excluded {excluded} package(s) using prefixes: {", ".join(prefixes) or "none"}.')
