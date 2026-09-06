"""Bounded MobSF workflow. The parent enforces a hard process deadline."""
import argparse
import hashlib
import os
from pathlib import Path
import time
from .core import write_json


class WorkflowError(Exception):
    """Fixed diagnostic messages safe to include in status evidence."""


def save(path, value):
    temporary = path.with_suffix(path.suffix + '.tmp')
    write_json(temporary, value)
    temporary.replace(path)


def valid_report(value, md5, sha256):
    return (isinstance(value, dict) and not value.get('error')
            and isinstance(value.get('md5'), str) and value['md5'].lower() == md5
            and isinstance(value.get('sha256'), str) and value['sha256'].lower() == sha256
            and isinstance(value.get('package_name'), str) and bool(value['package_name'])
            and isinstance(value.get('permissions'), dict)
            and isinstance(value.get('manifest_analysis'), (dict, list))
            and isinstance(value.get('code_analysis'), dict)
            and isinstance(value.get('certificate_analysis'), dict))


def run(args, session, clock=time.monotonic, sleep=time.sleep):
    import requests
    deadline = clock() + args.budget
    state = {'status': 'running', 'stage': 'hashing', 'attempts': 0}
    output = args.output

    def update(**values):
        state.update(values)
        save(output / 'status.json', state)

    def remaining():
        left = deadline - clock()
        if left <= 0:
            raise TimeoutError('workflow deadline')
        return left

    def pause():
        sleep(min(args.poll_seconds, remaining()))

    def request(endpoint, **kwargs):
        remaining()
        update(stage=endpoint, attempts=state['attempts'] + 1)
        # Scan can be synchronous and long-running. The parent still bounds it.
        timeout = remaining() if endpoint == 'scan' else min(args.timeout, remaining())
        record = {'endpoint': endpoint, 'attempt': state['attempts']}
        try:
            response = session.post(args.url + '/api/v1/' + endpoint,
                                    timeout=timeout, allow_redirects=False, **kwargs)
            record['http_status'] = response.status_code
            try:
                body = response.json()
            except ValueError:
                body = None
                record['invalid_json'] = True
            record['response'] = body
        except (requests.Timeout, requests.ConnectionError) as exc:
            record['transport_error'] = type(exc).__name__
            save(output / f'{state["attempts"]:04d}-{endpoint}.json', record)
            raise
        save(output / f'{state["attempts"]:04d}-{endpoint}.json', record)
        remaining()
        if 300 <= response.status_code < 400:
            raise WorkflowError('HTTP redirect refused.')
        return response.status_code, body

    try:
        update()
        md5, sha256 = hashlib.md5(usedforsecurity=False), hashlib.sha256()
        with args.apk.open('rb') as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b''):
                remaining()
                md5.update(block)
                sha256.update(block)
        digest, strong_digest = md5.hexdigest(), sha256.hexdigest()
        update(md5=digest, sha256=strong_digest)
        with args.apk.open('rb') as stream:
            code, upload = request('upload', files={'file': (args.apk.name, stream, 'application/octet-stream')})
        if code != 200 or not isinstance(upload, dict) or upload.get('error') or upload.get('hash') != digest:
            raise WorkflowError('Upload rejected or returned hash differs from the local APK.')
        save(output / 'upload.json', upload)
        task_id = None
        try:
            code, scan = request('scan', data={'hash': digest})
            if code not in (200, 202) or not isinstance(scan, dict) or scan.get('error'):
                raise WorkflowError('Scan request rejected or returned an error response.')
            save(output / 'scan.json', scan)
            task_id = scan.get('task_id')
            if task_id is not None and (not isinstance(task_id, str) or not task_id):
                raise WorkflowError('Scan returned an invalid task ID.')
        except (requests.Timeout, requests.ConnectionError):
            # Server may have accepted it. Do not submit another scan.
            update(scan_response='unknown')
        update(task_id=task_id)
        task_complete = task_id is None
        while True:
            remaining()
            try:
                if not task_complete:
                    code, tasks = request('tasks', data={})
                    if code in (429, 502, 503, 504) or (code == 400 and isinstance(tasks, dict) and tasks.get('error') == 'Scan queue empty'):
                        pause()
                        continue
                    if code != 200 or not isinstance(tasks, list):
                        raise WorkflowError('Task endpoint unavailable or returned an unrecognized response.')
                    task = next((task for task in tasks if isinstance(task, dict)
                                 and task.get('task_id') == task_id and task.get('checksum') == digest), None)
                    if task is None or not task.get('completed_at'):
                        pause()
                        continue
                    if task.get('status') != 'Success':
                        raise WorkflowError('Asynchronous scan completed unsuccessfully; inspect task evidence.')
                    task_complete = True
                code, report = request('report_json', data={'hash': digest})
            except (requests.Timeout, requests.ConnectionError):
                pause()
                continue
            if code in (429, 502, 503, 504) or (code in (200, 404) and isinstance(report, dict) and report.get('report') == 'Report not Found'):
                pause()
                continue
            if code != 200 or not valid_report(report, digest, strong_digest):
                raise WorkflowError('Report rejected, incomplete, or does not match the local APK hashes.')
            save(output / 'report_json.json', report)
            update(status='completed', stage='report_validated')
            return 0
    except TimeoutError:
        update(status='timed_out', reason='Overall MobSF deadline exceeded.')
    except WorkflowError as exc:
        update(status='failed', reason=str(exc))
    except Exception as exc:
        # Exception strings may contain credentials or server-controlled data.
        update(status='failed', reason=type(exc).__name__)
    return 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', required=True)
    parser.add_argument('--apk', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--budget', type=float, required=True)
    parser.add_argument('--timeout', type=float, required=True)
    parser.add_argument('--poll-seconds', type=float, required=True)
    args = parser.parse_args()
    import requests
    with requests.Session() as session:
        session.trust_env = False
        session.headers.update({'Authorization': os.environ['MOBSF_API_KEY']})
        return run(args, session)


if __name__ == '__main__':
    raise SystemExit(main())
