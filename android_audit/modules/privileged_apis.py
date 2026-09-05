from ..apps import collect_apps, record_manifest_checks, manifest_evidence
CATEGORY = 'running_applications'

def run(c):
    apps = collect_apps(c)
    record_manifest_checks(c, apps, 'privileged_apis')
    for app in apps:
        if app['privileged_candidate']:
            for manifest in app['manifests']:
                for component in manifest['components']:
                    if component['type'] in ('service', 'provider') and component['candidate_unguarded']:
                        c.finding('HW-APP-002',
                                  {'package': app['package'], **component}, 'medium', evidence=manifest_evidence(manifest, component=component['name'], type=component['type']))
    c.note('Privileged status is inferred from install path/package flags. Manifest exposure is not proof of exploitable privileged operations; verify runtime authorization and effective grants.')
