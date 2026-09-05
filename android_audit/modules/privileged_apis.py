from ..apps import collect_apps
CATEGORY = 'running_applications'

def run(c):
    for app in collect_apps(c):
        if app['privileged_candidate']:
            for manifest in app['manifests']:
                for component in manifest['components']:
                    if component['type'] in ('service', 'provider') and component['candidate_unguarded']:
                        c.finding('Privileged app API exposure candidate',
                                  {'package': app['package'], **component}, 'high')
    c.note('Privileged status is inferred from install path/package flags. Manifest exposure is not proof of exploitable privileged operations; verify runtime authorization and effective grants.')
