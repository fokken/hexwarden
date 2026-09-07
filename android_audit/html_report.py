"""Self-contained HTML rendering for a Hexwarden JSON report."""

from __future__ import annotations

import html
import json
from collections import Counter
from pathlib import Path


def _text(value):
    return html.escape(str(value), quote=True)


def _json(value):
    return _text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))


def _evidence(ref):
    path = str(ref.get('path', ''))
    label = _text(path)
    href = html.escape(path, quote=True)
    locator = f" <code>{_json(ref['locator'])}</code>" if ref.get('locator') else ''
    return f'<li><a href="{href}">{label}</a>{locator}</li>'


def render(document):
    summary = document.get('summary', {})
    findings = [finding for module in document.get('modules', []) for finding in module.get('findings', [])]
    severity = summary.get('by_severity', {})
    cards = ''.join(
        f'<div class="card"><strong>{_text(value)}</strong><span>{_text(label)}</span></div>'
        for label, value in (
            ('Findings', summary.get('findings', len(findings))),
            ('High severity', severity.get('high', 0)),
            ('Modules', len(document.get('modules', []))),
            ('Manual review', summary.get('modules_requiring_manual_verification', 0)),
        )
    )
    rule_counts = Counter(finding.get('rule_id', '') for finding in findings)

    def render_finding(finding, nested=False):
        refs = ''.join(_evidence(ref) for ref in finding.get('evidence', [])) or '<li>No evidence reference</li>'
        return f'''<details class="finding {"nested" if nested else ""} {html.escape(finding.get('severity', 'info'))}">
<summary><span class="badge">{_text(finding.get('severity', 'info'))}</span>
<strong>{_text(finding.get('rule_id', ''))}</strong> {_text(finding.get('title', ''))}</summary>
<div class="finding-body"><p><b>Classification:</b> {_text(finding.get('classification', ''))}
 &nbsp; <b>Confidence:</b> {_text(finding.get('confidence', ''))}
 &nbsp; <b>Status:</b> {_text(finding.get('verification_status', ''))}</p>
<p><b>Asset</b></p><pre>{_json(finding.get('asset', {}))}</pre>
<p><b>Detail</b></p><pre>{_json(finding.get('detail', {}))}</pre>
<p><b>Action:</b> {_text(finding.get('remediation', ''))}</p>
<p><b>Verify:</b> {_text(finding.get('verification', ''))}</p>
<p><b>Evidence</b></p><ul>{refs}</ul></div></details>'''
    finding_rows = []
    grouped = set()
    for finding in findings:
        rule_id = finding.get('rule_id', '')
        if rule_counts[rule_id] > 1:
            if rule_id in grouped:
                continue
            grouped.add(rule_id)
            members = [item for item in findings if item.get('rule_id', '') == rule_id]
            finding_rows.append(f'''<details class="finding-group">
<summary><strong>{_text(rule_id)}</strong> {_text(finding.get('title', ''))} <span class="muted">({len(members)} findings)</span></summary>
<div class="group-body">{''.join(render_finding(item, nested=True) for item in members)}</div></details>''')
        else:
            finding_rows.append(render_finding(finding))
    modules = []
    for module in document.get('modules', []):
        coverage = module.get('coverage', {})
        collection = coverage.get('collection', {}).get('status', module.get('status', ''))
        analysis = coverage.get('analysis', {}).get('status', '')
        modules.append(f'<tr><td>{_text(module.get("module", ""))}</td><td>{_text(module.get("category", ""))}</td>'
                       f'<td>{_text(collection)}</td><td>{_text(analysis)}</td>'
                       f'<td>{len(module.get("findings", []))}</td></tr>')
    limitation_items = []
    for module in document.get('modules', []):
        for limitation in module.get('limitations', []):
            limitation_items.append(f'<li><b>{_text(module.get("module", ""))}:</b> {_text(limitation)}</li>')
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Hexwarden report {_text(document.get('run_id', ''))}</title>
<style>
:root {{ color-scheme: light dark; --bg:#10151c; --panel:#18212c; --text:#e8eef5; --muted:#9eacba; --accent:#70b7ff; --danger:#ff7d7d; --line:#334252; }}
* {{ box-sizing:border-box }} body {{ margin:0; padding:2rem; background:var(--bg); color:var(--text); font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif }}
main {{ max-width:1200px; margin:auto }} h1,h2 {{ line-height:1.2 }} h1 {{ margin-bottom:.25rem }} h2 {{ margin-top:2rem }} .muted {{ color:var(--muted) }}
.cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:1rem; margin:1.5rem 0 }} .card, details, table {{ background:var(--panel); border:1px solid var(--line); border-radius:8px }} .card {{ padding:1rem }} .card strong {{ display:block; font-size:1.8rem }} .card span {{ color:var(--muted) }}
table {{ width:100%; border-collapse:collapse; overflow:hidden }} th,td {{ padding:.65rem .75rem; border-bottom:1px solid var(--line); text-align:left }} th {{ color:var(--muted) }}
details {{ margin:.7rem 0 }} summary {{ cursor:pointer; padding:.8rem 1rem }} .finding-body {{ padding:0 1rem 1rem }} .finding-group {{ border-color:#4b6075 }} .group-body {{ padding:.2rem .8rem .8rem }} .finding.nested {{ margin:.6rem 0; background:#121a23 }} .badge {{ border-radius:999px; padding:.15rem .5rem; margin-right:.5rem; background:#405267; font-size:.8rem; text-transform:uppercase }} .high .badge {{ background:#8c3030 }}
pre {{ padding:.8rem; overflow:auto; background:#0b1016; border-radius:5px; white-space:pre-wrap; overflow-wrap:anywhere }} a {{ color:var(--accent) }} code {{ color:var(--muted) }}
</style></head><body><main>
<h1>Hexwarden security report</h1><p class="muted">Run <b>{_text(document.get('run_id', ''))}</b> · Device {_text(document.get('device', ''))} · Status {_text(document.get('status', ''))}</p>
<div class="cards">{cards}</div>
<p>{_text(summary.get('interpretation', 'No findings does not mean secure.'))}</p>
<h2>Findings</h2>{''.join(finding_rows) or '<p class="muted">No findings were recorded.</p>'}
<h2>Modules</h2><table><thead><tr><th>Module</th><th>Category</th><th>Collection</th><th>Analysis</th><th>Findings</th></tr></thead><tbody>{''.join(modules)}</tbody></table>
<h2>Coverage limitations</h2><ul>{''.join(limitation_items) or '<li>None recorded.</li>'}</ul>
<h2>Scope</h2><pre>{_json(document.get('scope', {}))}</pre>
</main></body></html>\n'''


def write_html_report(json_path, html_path):
    document = json.loads(Path(json_path).read_text())
    Path(html_path).write_text(render(document))
