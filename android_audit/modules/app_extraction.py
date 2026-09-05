from ..apps import collect_apps, record_manifest_checks, manifest_evidence
from ..integrations import mobsf_scan
CATEGORY = 'running_applications'

def run(c):
    apps = collect_apps(c)
    record_manifest_checks(c, apps, 'debuggable_manifest')
    for app in apps:
        for manifest in app['manifests']:
            if manifest['application'].get('debuggable') == 'true':
                c.finding('HW-APP-004', app['package'], 'medium', 'high', asset={'device': c.args.serial, 'package': app['package']}, evidence=manifest_evidence(manifest, element='application', attribute='debuggable'))
        if c.args.mobsf_url:
            for apk in app['apks']:
                mobsf_scan(c, c.root / apk['path'])
    c.note('Extraction covers installed base/split APKs visible to ADB, not private app data or uninstalled firmware apps. Valid signing does not establish signer trust; compare fingerprints against approved baselines.')
