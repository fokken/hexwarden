"""Explicit optional integrations; no automatic tool installation or agent deployment."""
import os
import re
from urllib.parse import urlparse
from .core import write_json


def mobsf_scan(c, apk):
    try:
        import requests
    except ImportError:
        c.note('Install the mobsf extra to upload and scan APKs.')
        return
    key = os.environ.get('MOBSF_API_KEY')
    if not key:
        c.note('MOBSF_API_KEY is missing; MobSF skipped.')
        return
    url = c.args.mobsf_url.rstrip('/')
    name = apk.parent.name + '-' + apk.stem
    output = c.root / 'integrations' / 'mobsf' / name
    output.mkdir(parents=True, exist_ok=True)
    try:
        with requests.Session() as session:
            session.trust_env = False
            session.headers.update({'Authorization': key})
            with apk.open('rb') as stream:
                response = session.post(url + '/api/v1/upload', files={'file': (apk.name, stream, 'application/octet-stream')}, timeout=c.args.timeout, allow_redirects=False)
            response.raise_for_status()
            upload = response.json()
            if not isinstance(upload, dict) or not re.fullmatch(r'[0-9a-fA-F]{32}', str(upload.get('hash', ''))):
                raise ValueError('Invalid upload response')
            write_json(output / 'upload.json', upload)
            for endpoint, body in (('scan', {'hash': upload['hash']}), ('report_json', {'hash': upload['hash']})):
                response = session.post(url + '/api/v1/' + endpoint, data=body,
                                        timeout=c.args.integration_timeout, allow_redirects=False)
                response.raise_for_status()
                if response.is_redirect:
                    raise ValueError('Redirect refused')
                write_json(output / (endpoint + '.json'), response.json())
            c.result['evidence'].append({'path': str((output / 'report_json.json').relative_to(c.root)), 'kind': 'external_analysis'})
    except Exception as exc:
        c.note(f'MobSF failed for {name} ({type(exc).__name__}); inspect saved integration output. API credentials are not logged.')


def external(c, results=None):
    if results is None:
        results = []
    if c.args.drozer:
        results.append(c.start('drozer', 'integrations'))
        from .drozer_checks import run
        try:
            run(c)
        except KeyboardInterrupt:
            c.result['status'] = 'error'
            c.note('Drozer interrupted. Inspect raw probe_created events for temporary files whose cleanup was not confirmed.')
            raise
        except Exception as exc:
            c.result['status'] = 'error'
            c.note(f'Drozer integration failed: {type(exc).__name__}: {exc}')
    if c.args.emba_firmware:
        results.append(c.start('emba', 'integrations'))
        directory = c.root / 'integrations' / 'emba'
        directory.parent.mkdir(parents=True, exist_ok=True)
        c.command([c.args.emba, '-f', str(c.args.emba_firmware.resolve()), '-l', str(directory)],
                  'firmware_analysis', c.args.integration_timeout)
        c.note('EMBA analyzes the supplied firmware offline; it does not extract firmware via ADB. Use a prepared EMBA installation with its documented prerequisites.')
    return results
