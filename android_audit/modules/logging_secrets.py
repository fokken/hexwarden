import re
CATEGORY = 'running_applications'
PATTERNS = {
    'credential assignment': re.compile(r'(?i)\b(?:password|passwd|api[_-]?key|client[_-]?secret|access[_-]?token)\b\s*[=:]\s*["\x27]?[^\s"\x27,;]{4,}'),
    'bearer token': re.compile(r'(?i)\bBearer\s+[A-Za-z0-9._~+/-]{8,}'),
    'private key marker': re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
}

def detect(text):
    return [{'line': i, 'kind': kind} for i, line in enumerate(text.splitlines(), 1)
            for kind, pattern in PATTERNS.items() if pattern.search(line)]

def run(c):
    value = c.shell(f'logcat -d -v threadtime -t {c.args.log_lines}', 'logcat')
    c.check('logcat_secret_heuristics', value is not None)
    if value is not None:
        matches = detect(value)
        if matches:
            refs = [{**ref, 'locator': {'lines': sorted({match['line'] for match in matches})}} for ref in c.latest_evidence]
            c.finding('HW-LOG-001', {'matches': matches, 'values': 'omitted; inspect restricted raw evidence'}, 'medium', evidence=refs)
    c.note('Heuristic scan of a bounded log snapshot; false positives and missed secrets are possible. Raw evidence can contain sensitive values.')
