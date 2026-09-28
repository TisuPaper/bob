"""Self-contained HTML reports; no payloads, server, or external assets."""
from collections import Counter
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from .detectors import redact


LABELS = {"EMAIL": "Email address", "MY_IC": "Malaysian IC", "CARD": "Payment card",
          "ACCOUNT": "Account number", "LOG_RISK": "Potential logging risk"}


def safe(value):
    return escape(redact(str(value)), quote=True)


def cards(findings):
    output = []
    for f in findings:
        kind = f['kind']
        location = f"{f['source']}:{f['line']}" if f.get('source') else 'Source unknown'
        evidence = f.get('masked', 'No runtime evidence — review this logging call')
        log = f"{f['log']}:{f['log_line']}" if f.get('log') else 'Code scan only'
        output.append(f'''<article class="finding" data-kind="{safe(kind)}" data-origin="{safe(f['origin'])}">
          <div class="row"><span class="badge">{safe(LABELS.get(kind, kind))}</span><span class="muted">{safe(f['confidence'])}</span></div>
          <h3>{safe(location)}</h3><code>{safe(evidence)}</code>
          <details><summary>Trace &amp; suggested fix</summary>
          <dl><dt>Detected in</dt><dd>{safe(log)}</dd><dt>Observed path</dt><dd>{safe(f['path'])}</dd>
          <dt>Suggested fix</dt><dd>{safe(f['suggestion'])}</dd></dl></details></article>''')
    return '\n'.join(output)


def write_html(path, findings, *, before=None, suppressed=0):
    runtime = sum(f['origin'] == 'runtime' for f in findings)
    risks = len(findings) - runtime
    sites = len({(f['source'], f['line']) for f in findings if f.get('source')})
    shown = before if before is not None else findings
    counts = Counter(f['kind'] for f in shown)
    options = ''.join(f'<option value="{safe(k)}">{safe(LABELS.get(k, k))} ({v})</option>' for k, v in sorted(counts.items()))
    status = 'Review required' if findings else 'No detected findings'
    comparison = ''
    if before is not None:
        comparison = f'''<section class="verification"><div><span class="eyebrow">FIX VERIFICATION</span>
        <h2>{len(before)} before <span class="arrow">→</span> {len(findings)} after</h2>
        <p>Fresh execution and logs after applying masking fixes. The findings below are the original scan.</p></div>
        <span class="badge">{'Rerun has findings' if findings else 'Rerun clean'}</span></section>'''
    empty = '<div class="empty">No findings in this scan. Only exercised logs and supported patterns were checked.</div>' if not shown else ''
    after_section = f'<section><h2>After repair</h2>{cards(findings)}</section>' if before is not None and findings else ''
    page = '''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>PII Log Guard — Scan results</title>
<style>
:root{color-scheme:light;--ink:#132c37;--muted:#5c707b;--teal:#086b60;--line:#dce5e7}
*{box-sizing:border-box}body{margin:0;background:#f3f6f7;color:var(--ink);font:16px/1.6 system-ui,sans-serif}
header{background:#122f39;color:white;padding:32px max(24px,calc((100vw - 1080px)/2)) 44px}
.brand{font-size:14px;letter-spacing:.14em;font-weight:750;color:#8edace}h1{font-size:clamp(30px,5vw,44px);line-height:1.15;margin:18px 0 12px}
header p{color:#bfd0d5;margin:0;max-width:720px}main{max-width:1128px;margin:auto;padding:28px 24px 60px}
.row{display:flex;justify-content:space-between;gap:12px;align-items:center;flex-wrap:wrap}.muted{color:var(--muted);font-size:13px}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin:24px 0}.stat,.finding,.verification,.empty{background:white;border:1px solid var(--line);border-radius:12px;padding:22px}
.stat strong{display:block;font-size:36px;line-height:1.2}.stat span{color:var(--muted);font-size:14px}
.badge{display:inline-block;border-radius:20px;background:#e7f4f0;color:#075f55;padding:4px 12px;font-size:13px;font-weight:650}
.verification{display:flex;align-items:center;justify-content:space-between;gap:20px;border-left:4px solid var(--teal);margin-bottom:28px}.verification h2{margin:4px 0;font-size:30px}.verification p{margin:0;color:var(--muted)}.eyebrow{font-size:12px;letter-spacing:.1em;font-weight:700;color:var(--teal)}.arrow{color:var(--teal)}
.controls{display:flex;gap:14px;flex-wrap:wrap;margin:18px 0}label{font-size:13px;color:var(--muted);display:grid;gap:4px}input,select{font:inherit;background:white;color:var(--ink);border:1px solid #aabbc2;border-radius:7px;padding:10px;min-height:44px}input{min-width:260px}
.finding{margin:12px 0}.finding h3{font-size:15px;overflow-wrap:anywhere;margin:16px 0 10px}code{display:block;background:#f1f5f6;padding:12px;border-radius:6px;overflow-wrap:anywhere;font-size:13px}
summary{cursor:pointer;font-size:14px;color:var(--teal);font-weight:650;padding-top:16px}dl{font-size:14px}dt{font-weight:650;margin-top:12px}dd{margin:3px 0;color:var(--muted);overflow-wrap:anywhere}footer{font-size:13px;color:var(--muted);margin-top:28px}h2{font-size:22px}button:focus-visible,input:focus-visible,select:focus-visible,summary:focus-visible{outline:3px solid #32b29b;outline-offset:3px}[hidden]{display:none!important}
@media(max-width:600px){.stats{gap:8px}.stat{padding:14px}.stat strong{font-size:28px}.verification{display:block}.verification .badge{margin-top:14px}input,select{width:100%}.controls label{width:100%}}
</style></head><body>
'''
    page += f'''<header><div class="brand">PII LOG GUARD</div><h1>Know what reached your logs.</h1>
<p>Review detected data types, masked evidence, and the logging statements that need attention.</p></header>
<main><div class="row"><span class="badge">{status}</span><span class="muted">Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</span></div>
<div class="stats"><div class="stat"><strong>{runtime}</strong><span>Observed PII matches{' after repair' if before is not None else ''}</span></div>
<div class="stat"><strong>{risks}</strong><span>Static risks{' after repair' if before is not None else ''}</span></div>
<div class="stat"><strong>{sites}</strong><span>Source locations with findings{' after repair' if before is not None else ''}</span></div></div>
{comparison}<section id="results"><h2>{'Before repair' if before is not None else 'Scan findings'}</h2>
<p class="muted">{suppressed} finding(s) excluded by baseline. Static risks are heuristics; runtime matches are observed patterns.</p>
<div class="controls"><label>Search location or evidence<input id="search" type="search" placeholder="Search findings…"></label>
<label>Data type<select id="kind"><option value="">All types</option>{options}</select></label>
<label>Evidence<select id="origin"><option value="">All evidence</option><option value="runtime">Runtime logs</option><option value="static">Static code</option></select></label></div>
<p id="count" class="muted" aria-live="polite">{len(shown)} findings shown</p>{cards(shown)}{empty}
<p id="no-match" class="empty" hidden>No findings match these filters.</p></section>{after_section}
<footer>Detected values are masked. No raw log payloads are embedded. Source locations come from code or log metadata.
A clean scan covers only supported patterns and the logs supplied; it is not proof that all sensitive data is absent.</footer></main>'''
    page += '''<script>
const fields=['search','kind','origin'].map(id=>document.getElementById(id));
const items=[...document.querySelectorAll('#results .finding')];
function filter(){const [search,kind,origin]=fields.map(el=>el.value.toLowerCase());let count=0;
for(const item of items){const show=(!search||item.textContent.toLowerCase().includes(search))&&(!kind||item.dataset.kind.toLowerCase()===kind)&&(!origin||item.dataset.origin===origin);item.hidden=!show;if(show)count++;}
document.getElementById('count').textContent=count+' of '+items.length+' findings shown';
document.getElementById('no-match').hidden=count!==0||items.length===0;}
fields.forEach(el=>el.addEventListener('input',filter));
</script></body></html>'''
    Path(path).write_text(page, encoding='utf-8')
