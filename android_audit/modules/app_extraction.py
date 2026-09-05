from ..apps import collect_apps
from ..integrations import mobsf_scan
CATEGORY = 'running_applications'

def run(c):
    apps = collect_apps(c)
    for app in apps:
        for manifest in app['manifests']:
            if manifest['application'].get('debuggable') == 'true':
                c.finding('Debuggable application', app['package'], 'medium', 'high')
        if c.args.mobsf_url:
            for apk in app['apks']:
                mobsf_scan(c, c.root / apk['path'])
    c.note('Extraction covers installed base/split APKs visible to ADB, not private app data or uninstalled firmware apps. Valid signing does not establish signer trust; compare fingerprints against approved baselines.')
