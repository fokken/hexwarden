from ..apps import collect_apps, record_manifest_checks, manifest_evidence
from ..app_trust import report_signers
CATEGORY = 'running_applications'

def run(c):
    apps = collect_apps(c)
    record_manifest_checks(c, apps, 'debuggable_manifest')
    report_signers(c, apps)
    for app in apps:
        for manifest in app['manifests']:
            if manifest['application'].get('debuggable') == 'true':
                c.finding('HW-APP-004', app['package'], 'medium', 'high', asset={'device': c.args.serial, 'package': app['package']}, evidence=manifest_evidence(manifest, element='application', attribute='debuggable'))
    c.note('Extraction covers installed base/split APKs visible to ADB, not private app data or uninstalled firmware apps. Valid signing and absence from a certificate blocklist do not establish signer trust.')
