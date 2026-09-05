from ..apps import collect_apps, record_manifest_checks, manifest_evidence
CATEGORY = 'running_applications'

def run(c):
    apps = collect_apps(c)
    record_manifest_checks(c, apps, 'app_apis')
    for app in apps:
        for manifest in app['manifests']:
            for component in manifest['components']:
                if component['candidate_unguarded']:
                    c.finding('HW-APP-001',
                              {'package': app['package'], **component}, 'medium', evidence=manifest_evidence(manifest, component=component['name'], type=component['type']))
    c.note('Candidates may be intentionally public. Runtime checks, URI grants, path permissions, resource references, split-manifest merging and per-user component overrides need manual validation. No component is invoked.')
