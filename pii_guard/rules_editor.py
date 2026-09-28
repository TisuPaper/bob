"""Local rules editor and validated atomic persistence."""
import json
from pathlib import Path
import tempfile
from .detectors import parse_rules


def save_rules(path, data):
    parse_rules(data)
    destination = Path(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=destination.parent,
                                         prefix='.rules-', suffix='.json', delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(data, stream, indent=2)
            stream.write('\n')
        temporary.replace(destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def editor_html(token):
    return PAGE.replace('__TOKEN__', json.dumps(token)).encode('utf-8')


PAGE = '''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Custom rules · logVeil</title>
<style>
*{box-sizing:border-box}body{margin:0;background:#f3f6f7;color:#132c37;font:16px/1.6 system-ui,sans-serif}main{max-width:980px;margin:40px auto;padding:0 24px}a{color:#086b60}h1{font-size:36px;margin-bottom:8px}.panel{background:white;border:1px solid #dce5e7;border-radius:12px;padding:24px;margin:24px 0}.fields{display:grid;grid-template-columns:1fr 2fr;gap:16px}label{display:grid;gap:6px;font-size:14px}input,textarea,button{font:inherit;border-radius:6px;padding:10px;border:1px solid #aabbc2}textarea{width:100%;min-height:330px;font:14px/1.6 monospace;tab-size:2}button{cursor:pointer;background:#086b60;color:white;border:0;min-height:44px;margin:16px 8px 0 0}button:disabled{opacity:.5}small,p{color:#526b76}#status{white-space:pre-wrap;font-weight:600}input:focus-visible,textarea:focus-visible,button:focus-visible{outline:3px solid #32b29b;outline-offset:2px}@media(max-width:640px){.fields{grid-template-columns:1fr}}
</style></head><body><main><a href="/">← Scan results</a><h1>Custom detection rules</h1>
<p>Add formats your organisation needs to detect. Built-in detectors remain enabled.</p>
<section class="panel"><h2>Add a pattern</h2><div class="fields">
<label>Rule name<input id="kind" placeholder="EMPLOYEE_ID"></label>
<label>Regex pattern<input id="pattern" placeholder="EMP-[0-9]{6}"></label>
<label>Capture group (optional)<input id="group" placeholder="secret"></label>
<label>Trailing characters to keep<input id="keep" type="number" min="0" max="4" value="0"></label>
</div><button id="add" disabled>Add to draft</button><small>Use ordinary regex backslashes here; JSON escaping is automatic.</small></section>
<section class="panel"><h2>Rules configuration</h2><p>Edit or remove rules in the draft below. Changes are written only when you save.</p>
<label for="config">JSON draft</label><textarea id="config" spellcheck="false" disabled></textarea>
<button id="validate" disabled>Validate draft</button><button id="save" disabled>Save rules</button>
<p id="status" role="status" aria-live="polite">Loading configuration…</p></section>
<p>After saving, rerun your scan with this rules file and regenerate the HTML report. Restart applications that cache rules through LOGVEIL_RULES. Saving does not run scans or modify application code.</p>
</main><script>
const token=__TOKEN__,config=document.getElementById('config'),status=document.getElementById('status');
const buttons=['add','validate','save'].map(id=>document.getElementById(id));
let revision=null;
function message(text){status.textContent=text;}
async function request(path,options={}){const response=await fetch(path,options);const result=await response.json();if(!response.ok)throw new Error(result.error||'Request failed');return result;}
async function load(){try{const result=await request('/api/rules');config.value=JSON.stringify(result.config,null,2);revision=result.revision;config.disabled=false;buttons.forEach(b=>b.disabled=false);message('Loaded. Changes are not saved automatically.');}catch(error){message(error.message);}}
document.getElementById('add').onclick=()=>{try{const data=JSON.parse(config.value);const rule={kind:document.getElementById('kind').value.trim(),pattern:document.getElementById('pattern').value};const group=document.getElementById('group').value.trim();if(group)rule.group=group;rule.keep_last=Number(document.getElementById('keep').value);data.rules.push(rule);config.value=JSON.stringify(data,null,2);message('Added to draft. Validate and save when ready.');}catch(error){message('Check the JSON draft: '+error.message);}};
async function submit(action){buttons.forEach(b=>b.disabled=true);try{const data=JSON.parse(config.value);const result=await request('/api/rules/'+action,{method:'POST',headers:{'Content-Type':'application/json','X-PII-Token':token},body:JSON.stringify({config:data,revision})});if(result.revision)revision=result.revision;message(action==='save'?'Saved. Rerun your scan to update the report.':'Valid configuration. Nothing has been saved.');}catch(error){message(error.message);}finally{buttons.forEach(b=>b.disabled=false);}}
document.getElementById('validate').onclick=()=>submit('validate');document.getElementById('save').onclick=()=>submit('save');config.addEventListener('input',()=>message('Unsaved draft.'));load();
</script></body></html>'''
