"""Explicit optional integrations; no automatic tool installation or agent deployment."""
import os
from .core import write_json


def mobsf_scan(c, apk):
    import importlib.util
    import json
    import sys
    from .mobsf_worker import valid_report
    scope = str(apk.relative_to(c.root))
    if importlib.util.find_spec('requests') is None or not os.environ.get('MOBSF_API_KEY'):
        reason = 'MobSF requires the mobsf extra and MOBSF_API_KEY.'
        c.check('mobsf_report', False, scope=scope, evidence=[], reason=reason)
        c.note(reason)
        return
    name = apk.parent.name + '-' + apk.stem
    output = c.root / 'integrations' / 'mobsf' / name
    output.mkdir(parents=True, exist_ok=True)
    status_path = output / 'status.json'
    write_json(status_path, {'status': 'running', 'stage': 'starting'})
    interrupted = False
    try:
        c.command([sys.executable, '-m', 'android_audit.mobsf_worker',
                   '--url', c.args.mobsf_url.rstrip('/'), '--apk', str(apk.resolve()),
                   '--output', str(output.resolve()), '--budget', str(c.args.integration_timeout),
                   '--timeout', str(c.args.timeout),
                   '--poll-seconds', str(c.args.mobsf_poll_seconds)],
                  'mobsf_' + name, c.args.integration_timeout)
    except KeyboardInterrupt:
        interrupted = True
        raise
    finally:
        status = json.loads(status_path.read_text())
        if status.get('status') == 'running':
            timed_out = any(e.get('label') == 'mobsf_' + name and e.get('timed_out')
                            for e in c.result['evidence'])
            status.update(status='interrupted' if interrupted else 'timed_out' if timed_out else 'failed',
                          reason='Worker ended before report validation; server scan may still be running.')
            write_json(status_path, status)
        complete = status.get('status') == 'completed'
        report_path = output / 'report_json.json'
        if complete:
            try:
                complete = valid_report(json.loads(report_path.read_text()), status['md5'], status['sha256'])
            except (OSError, ValueError, KeyError, AttributeError):
                complete = False
            if not complete:
                status.update(status='failed', reason='Saved report validation failed.')
                write_json(status_path, status)
        refs = []
        for path in sorted(output.glob('*.json')):
            ref = {'path': str(path.relative_to(c.root)),
                   'kind': 'external_analysis' if complete and path == report_path else 'integration_status'}
            c.result['evidence'].append(ref)
            if path in (status_path, report_path):
                refs.append(ref)
        c.check('mobsf_report', complete, scope=scope, evidence=refs,
                reason=None if complete else 'MobSF report unavailable or incomplete; inspect status and response evidence.')
        if not complete:
            c.note(f'MobSF {status["status"]} for {name}; inspect saved integration status. Server work is not cancelled.')
        else:
            c.note('MobSF report identity and core analysis sections validated. External findings remain separate; '
                   'report availability does not establish completeness of every MobSF analyzer.')


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
