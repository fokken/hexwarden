from ..apps import collect_apps
CATEGORY = 'running_applications'

def run(c):
    for app in collect_apps(c):
        for manifest in app['manifests']:
            for component in manifest['components']:
                if component['candidate_unguarded']:
                    c.finding('Exported component without manifest permission',
                              {'package': app['package'], **component}, 'medium')
    c.note('Candidates may be intentionally public. Runtime checks, URI grants, path permissions, resource references, split-manifest merging and per-user component overrides need manual validation. No component is invoked.')
