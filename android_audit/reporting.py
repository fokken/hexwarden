"""Coverage and summaries never turn absence of findings into a pass."""
from collections import Counter


def module_coverage(result):
    commands = {e['path']: e for e in result['evidence'] if 'returncode' in e}
    succeeded = sum(bool(e.get('ok')) for e in commands.values())
    failed = len(commands) - succeeded
    skipped = len(result.get('skipped_checks', []))
    truncated = sum(bool(e.get('analysis_truncated')) for e in commands.values())
    if commands:
        collection = 'partial' if failed or skipped else 'completed'
        if not succeeded:
            collection = 'failed'
    elif result['status'] == 'skipped' or skipped:
        collection = 'skipped'
    else:
        collection = 'not_performed'
    checks = result.get('analysis_checks', [])
    evaluated = sum(check['status'] == 'evaluated' for check in checks)
    if not checks:
        analysis = 'not_performed'
    elif evaluated == len(checks) and not truncated:
        analysis = 'completed'
    elif evaluated:
        analysis = 'partial'
    else:
        analysis = 'not_performed'
    if result['status'] == 'error':
        analysis = 'partial' if evaluated else 'failed'
    if result.get('interrupted'):
        collection = 'partial' if commands else 'not_performed'
        analysis = 'partial' if evaluated else 'not_performed'
    reasons = list(result['limitations'])
    if not checks:
        reasons.append('No automated analysis recorded; collected evidence requires manual interpretation.')
    elif evaluated < len(checks):
        reasons.append('Some automated checks could not be evaluated.')
    if any(f['classification'] == 'review_candidate' for f in result['findings']):
        reasons.append('Review candidates require the finding-specific verification steps.')
    if result.get('interrupted'):
        reasons.append('Module interrupted; evidence and analysis are incomplete.')
    if truncated:
        reasons.append('Automated analysis used truncated command output; inspect the complete raw evidence.')
    result['coverage'] = {
        'collection': {'status': collection, 'attempted_commands': len(commands), 'succeeded_commands': succeeded,
                       'failed_commands': failed, 'skipped_commands': skipped, 'truncated_outputs': truncated},
        'analysis': {'status': analysis, 'recorded_checks': len(checks), 'evaluated_checks': evaluated,
                     'not_evaluated_checks': len(checks) - evaluated},
        'manual_verification': {'required': bool(reasons), 'reasons': list(dict.fromkeys(reasons))},
    }
    return result['coverage']


def summarize(document):
    modules = document['modules']
    for module in modules:
        module_coverage(module)
    findings = [f for m in modules for f in m['findings']]
    requested = document.get('requested_modules', [])
    started = {m['module'] for m in modules}
    document['summary'] = {
        'findings': len(findings), 'by_severity': dict(Counter(f['severity'] for f in findings)),
        'by_classification': dict(Counter(f['classification'] for f in findings)),
        'collection': dict(Counter(m['coverage']['collection']['status'] for m in modules)),
        'analysis': dict(Counter(m['coverage']['analysis']['status'] for m in modules)),
        'modules_requiring_manual_verification': sum(m['coverage']['manual_verification']['required'] for m in modules),
        'requested_modules_not_started': [m for m in requested if m not in started],
        'interpretation': 'No findings does not mean secure. Completed analysis covers only the explicitly recorded checks.',
    }
