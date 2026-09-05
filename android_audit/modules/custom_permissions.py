from ..apps import collect_apps
CATEGORY = 'running_applications'

def run(c):
    c.shell('pm list permissions -f', 'permissions')
    for app in collect_apps(c):
        for manifest in app['manifests']:
            for permission in manifest['permissions']:
                if permission['weak']:
                    c.finding('Custom permission with weak protection level',
                              {'package': app['package'], **permission}, 'medium')
    c.note('Normal/dangerous protection is a review candidate, not proof of abuse. Resolve permission ownership, consumers, install order and signature/privileged allowlists.')
