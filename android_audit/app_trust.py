"""Explicit certificate trust policy, separate from cryptographic verification."""
import json
import re
from .core import write_json


def fingerprint(value):
    if not isinstance(value, str):
        raise ValueError('certificate fingerprints must be strings')
    value = value.replace(':', '').strip().lower()
    if not re.fullmatch(r'[0-9a-f]{64}', value):
        raise ValueError('expected a SHA-256 certificate fingerprint (64 hexadecimal digits)')
    return value


def load_policy(path):
    value = json.loads(path.read_text())
    if not isinstance(value, dict) or set(value) - {'default', 'packages'}:
        raise ValueError('expected an object containing only default and packages')
    packages = value.get('packages', {})
    if not isinstance(packages, dict) or any(not re.fullmatch(r'[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*', key) for key in packages):
        raise ValueError('packages must map exact package names to fingerprint lists')
    def normalize(values):
        if not isinstance(values, list):
            raise ValueError('each allowlist must be a list of certificate fingerprints')
        return sorted({fingerprint(item) for item in values})
    return {'default': normalize(value.get('default', [])),
            'packages': {key: normalize(items) for key, items in packages.items()}}


def parse_signature(output):
    # Only current APK signers; never source-stamp or public-key digests.
    if output is None:
        return {'status': 'verification_failed_or_unavailable', 'sha256': []}
    matches = re.findall(r'^Signer #\d+ certificate SHA-256 digest: ([0-9a-fA-F:]+)\s*$', output, re.M)
    lines = re.findall(r'^Signer #\d+ certificate SHA-256 digest:.*$', output, re.M)
    counts = re.findall(r'^Number of signers: (\d+)\s*$', output, re.M)
    try:
        digests = sorted({fingerprint(value) for value in matches})
    except ValueError:
        digests = []
    if len(lines) != len(matches) or (counts and int(counts[-1]) != len(matches)):
        digests = []
    return {'status': 'verified' if digests else 'unparsed', 'sha256': digests}


def signer_status(signature, allowed):
    if signature.get('status') != 'verified' or not signature.get('sha256'):
        return 'not_evaluated'
    return 'approved' if set(signature['sha256']) <= set(allowed) else 'unapproved'


def report_signers(c, apps):
    policy = getattr(c.args, 'signer_policy', None)
    if policy is None:
        c.check('approved_signers', False, evidence=[], reason='No --approved-certs policy supplied.')
        return
    policy_path = c.directory / 'approved-certs.json'
    write_json(policy_path, policy)
    policy_ref = {'path': str(policy_path.relative_to(c.root)), 'kind': 'policy'}
    c.result['evidence'].append(policy_ref)
    rows = []
    if not apps:
        c.check('approved_signers', False, evidence=[policy_ref], reason='No packages collected.')
    for app in apps:
        allowed = policy['packages'].get(app['package'], policy['default'])
        if not app['apks']:
            c.check('approved_signers', False, scope=app['package'], evidence=[], reason='No APKs extracted.')
        for apk in app['apks']:
            signature = apk.get('signature', {})
            status = signer_status(signature, allowed)
            row = {'package': app['package'], 'apk': apk['path'], 'status': status,
                   'signature': signature, 'allowed_sha256': allowed}
            rows.append(row)
            refs = signature.get('evidence', []) + [policy_ref]
            c.check('approved_signers', status != 'not_evaluated',
                    scope={'package': app['package'], 'apk': apk['path']}, evidence=refs,
                    reason='Signature verification or fingerprint extraction unavailable.' if status == 'not_evaluated' else None)
            if status == 'unapproved':
                c.finding('HW-APP-009', row, 'medium', 'high',
                          asset={'device': c.args.serial, 'package': app['package'], 'apk': apk['path']}, evidence=refs)
    path = c.directory / 'signer-policy.json'
    write_json(path, rows)
    c.result['evidence'].append({'path': str(path.relative_to(c.root)), 'kind': 'derived'})
    c.note('Signer approval is per extracted APK and requires every reported current signer to be allowed. '
           'Package overrides replace the default list. Rotation lineage, device-specific signer selection '
           'and missing splits require review; approval does not establish application safety.')
