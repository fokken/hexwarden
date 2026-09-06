from ..apps import collect_apps, record_manifest_checks, manifest_evidence
from ..permission_map import report_permissions
CATEGORY = 'running_applications'

def run(c):
    c.shell('pm list permissions -f', 'permissions')
    apps = collect_apps(c)
    record_manifest_checks(c, apps, 'custom_permissions')
    report_permissions(c, apps)
    for app in apps:
        for manifest in app['manifests']:
            for permission in manifest['permissions']:
                if permission['weak']:
                    c.finding('HW-APP-003',
                              {'package': app['package'], **permission}, 'medium', evidence=manifest_evidence(manifest, permission=permission['name']))
    c.note('Normal/dangerous protection is a review candidate, not proof of abuse. Resolve permission ownership, consumers, install order and signature/privileged allowlists.')
