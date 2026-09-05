import re
import shlex
import shutil
from ..core import write_json
CATEGORY = 'system_hardening'


def run(c):
    stores = [('system', '/system/etc/security/cacerts', False),
              ('conscrypt', '/apex/com.android.conscrypt/cacerts', False),
              ('user', f'/data/misc/user/{c.args.user}/cacerts-added', True)]
    certificates = []
    for store, directory, privileged in stores:
        listing = c.shell('ls -1 ' + shlex.quote(directory), store + '_ca', root=privileged)
        if not listing:
            continue
        for name in listing.splitlines():
            if not re.fullmatch(r'[0-9a-fA-F]{8}\.\d+', name.strip()):
                continue
            name = name.strip()
            if c.shell('cat ' + shlex.quote(directory + '/' + name), store + '_' + name,
                       root=privileged, binary=True) is None:
                continue
            record = c.result['evidence'][-1]
            if not record.get('ok'):
                continue
            path = c.root / record['path']
            if not shutil.which('openssl'):
                c.note('Host openssl unavailable; certificate bytes retained without X.509 inspection.')
                continue
            with path.open('rb') as stream:
                form = 'PEM' if stream.read(32).startswith(b'-----BEGIN') else 'DER'
            value = c.command(['openssl', 'x509', '-in', str(path), '-inform', form,
                               '-noout', '-subject', '-issuer', '-dates', '-fingerprint', '-sha256'],
                              'x509_' + store + '_' + name)
            c.check('test_ca_subject_heuristic', bool(value) and 'subject=' in value, scope=store + '/' + name)
            if value:
                certificates.append({'store': store, 'name': name, 'details': value})
                if re.search(r'(?im)^subject=.*\b(debug|test|testing)\b', value):
                    c.finding('HW-CA-001', {'store': store, 'name': name,
                              'details': value}, 'medium', 'low')
    write_json(c.directory / 'certificates.json', certificates)
    c.result['evidence'].append({'path': str((c.directory / 'certificates.json').relative_to(c.root)), 'kind': 'derived'})
    c.shell('dumpsys device_policy', 'certificate_policy')
    c.note('Subject-name heuristics do not prove test/debug key use. Compare SHA-256 fingerprints against an approved trust baseline. Removed CAs, OEM stores and app network-security configs require separate review; system-store presence does not prove every app trusts a CA.')
