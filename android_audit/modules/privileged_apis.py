from ..apps import collect_apps, record_manifest_checks, manifest_evidence
CATEGORY = 'running_applications'
DEFAULT_EXCLUDED_PREFIXES = ('com.google', 'com.android')


def excluded_prefixes(c):
    configured = tuple(getattr(c.args, 'privileged_api_exclude_prefix', []) or [])
    defaults = () if getattr(c.args, 'privileged_api_no_default_excludes', False) else DEFAULT_EXCLUDED_PREFIXES
    return tuple(dict.fromkeys((*defaults, *configured)))

def run(c):
    apps = collect_apps(c)
    record_manifest_checks(c, apps, 'privileged_apis')
    prefixes = excluded_prefixes(c)
    excluded = 0
    for app in apps:
        if any(app['package'].startswith(prefix) for prefix in prefixes):
            excluded += 1
            continue
        if app['privileged_candidate']:
            for manifest in app['manifests']:
                for component in manifest['components']:
                    if component['type'] in ('service', 'provider') and component['candidate_unguarded']:
                        c.finding('HW-APP-002',
                                  {'package': app['package'], **component}, 'medium', evidence=manifest_evidence(manifest, component=component['name'], type=component['type']))
    c.note('Privileged status is inferred from install path/package flags. Manifest exposure is not proof of exploitable privileged operations; verify runtime authorization and effective grants.')
    c.note(f'HW-APP-002 package filter excluded {excluded} package(s) using prefixes: {", ".join(prefixes) or "none"}.')
