"""Private, self-contained HTML snapshots of the offline workbench.

This module intentionally publishes an allowlisted projection of application data.
In particular, job specifications, engine output, file paths, and recovered values
must never be serialized into an HTML snapshot, including hidden script elements.
"""

from __future__ import annotations

import html
import json
import os
import tempfile
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit


def _text(value: object, limit: int = 12000) -> str:
    """Treat descriptions as text, never as HTML or nested serialized objects."""
    if isinstance(value, str):
        return value[:limit]
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    return ""


def _count(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def _link(value: object) -> str:
    if not isinstance(value, str) or any(ord(c) < 32 for c in value):
        return ""
    try:
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return ""
        if parsed.username is not None or parsed.password is not None:
            return ""
        # Reading .port also rejects malformed host/port combinations.
        parsed.port
    except ValueError:
        return ""
    return value


def _strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [_text(value)]
    if isinstance(value, list):
        return [_text(item) for item in value[:20] if isinstance(item, str)]
    return []


def _job_projection(jobs: list[dict]) -> list[dict]:
    return [
        {key: _text(job.get(key), 256) for key in ("id", "status", "created_at")}
        for job in jobs if isinstance(job, dict)
    ]


def _backlog_projection(backlog: list[dict]) -> list[dict]:
    result = []
    for row in backlog:
        if not isinstance(row, dict):
            continue
        result.append({
            "id": _text(row.get("id"), 64),
            "category": _text(row.get("category"), 256),
            "idea": _text(row.get("idea")),
            "priority": _text(row.get("priority"), 16),
            "effort": _text(row.get("effort"), 16),
            "status": _text(row.get("status", "planned"), 80),
            # Evidence may contain internal filesystem paths; keep it in the
            # detailed JSON/report and publish only idea/status in this view.
        })
    return result


def _integration_projection(integrations: list[dict]) -> list[dict]:
    result = []
    for row in integrations:
        if not isinstance(row, dict):
            continue
        sources = []
        for source in _strings(row.get("sources")):
            url = _link(source)
            if url and url not in sources:
                sources.append(url)
        result.append({
            "repo": _text(row.get("repo") or row.get("name"), 256),
            "url": _link(row.get("url")),
            "description": _text(row.get("description")),
            "decision": _text(row.get("decision", "needs-review"), 80),
            "reason": _text(row.get("reason")),
            "license": _text(row.get("license"), 512),
            "head_sha": _text(row.get("head_sha"), 64),
            "observations": _strings(row.get("observations")),
            "sources": sources,
        })
    return result


def _safe_json(value: object) -> str:
    # Script elements are raw text, so HTML escaping is not sufficient here.
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":"))
            .replace("<", "\\u003c").replace(">", "\\u003e")
            .replace("&", "\\u0026").replace("\u2028", "\\u2028")
            .replace("\u2029", "\\u2029"))


def render_dashboard(summary: dict, jobs: list[dict], integrations: list[dict],
                     backlog: list[dict]) -> str:
    """Return a standalone snapshot with local search and no network requests.

    An integration's source description is shown as an upstream claim. Catalog
    membership and a completed research review never imply executable integration.
    """
    safe_jobs = _job_projection(jobs)
    safe_backlog = _backlog_projection(backlog)
    safe_integrations = _integration_projection(integrations)
    statuses = Counter(row["status"] for row in safe_backlog)
    metrics = {
        "asset_count": _count(summary.get("asset_count")),
        "asset_bytes": _count(summary.get("asset_bytes")),
        "job_count": _count(summary.get("job_count")),
    }
    data = {"jobs": safe_jobs, "backlog": safe_backlog, "integrations": safe_integrations}
    replacements = {
        "__DATA__": _safe_json(data),
        "__ASSETS__": str(metrics["asset_count"]),
        "__BYTES__": f'{metrics["asset_bytes"]:,}',
        "__JOBS__": str(metrics["job_count"]),
        "__IDEAS__": str(len(safe_backlog)),
        "__IMPLEMENTED__": str(statuses.get("implemented", 0)),
        "__PARTIAL__": str(statuses.get("partial", 0)),
        "__PROJECTS__": str(len(safe_integrations)),
        "__JOB_FALLBACK__": "".join(
            "<tr>" + "".join("<td>" + html.escape(job[k]) + "</td>"
                              for k in ("id", "status", "created_at")) + "</tr>"
            for job in safe_jobs
        ) or '<tr><td colspan="3">No jobs recorded in this snapshot.</td></tr>',
    }
    document = _TEMPLATE
    # Data is substituted last, preventing user strings resembling template
    # placeholders from being interpreted as another replacement instruction.
    for marker, value in replacements.items():
        if marker != "__DATA__":
            document = document.replace(marker, value)
    return document.replace("__DATA__", replacements["__DATA__"])


def write_dashboard(path: Path, summary: dict, jobs: list[dict],
                    integrations: list[dict], backlog: list[dict]) -> Path:
    """Atomically publish a mode-0600 HTML snapshot in a caller-chosen location.

    New parent directories use mode 0700. Existing directory permissions are not
    changed. Replacing a final symlink replaces the link, not its target.
    """
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    document = render_dashboard(summary, jobs, integrations, backlog)
    fd, temporary = tempfile.mkstemp(prefix=".dashboard-", suffix=".tmp", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(document)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        # Best-effort directory durability where the platform supports it.
        if hasattr(os, "O_DIRECTORY"):
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return path


def render_team_shell() -> str:
    """Return the shared-server interface; bearer credentials stay in memory.

    The server remains responsible for authorization, request validation, job
    ownership, and upload limits. Hiding disabled controls is only a UI affordance.
    """
    return _TEAM_TEMPLATE


_TEAM_TEMPLATE = '''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-src 'self' about:; base-uri 'none'; form-action 'none'">
<title>JEFFE Ultimate — team workspace</title>
<style>
:root{color-scheme:dark;--bg:#10191e;--panel:#19272e;--ink:#ecf4f2;--muted:#aec3ca;--accent:#69e5c0;--border:#34505b;--gold:#eccc81}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.55 system-ui,sans-serif}main{max-width:1240px;margin:auto;padding:28px 24px 60px}h1{font-size:clamp(2rem,5vw,3.5rem);letter-spacing:-.04em;line-height:1.05;margin:16px 0}h2{font-size:1.3rem;margin:0 0 12px}h3{font-size:1rem;margin:0 0 10px}.eyebrow{font-size:.76rem;letter-spacing:.16em;font-weight:800;color:var(--accent)}.muted,small{color:var(--muted)}.panel{padding:22px;border:1px solid var(--border);border-radius:14px;background:var(--panel);margin-top:18px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}.grid .panel{margin-top:0}label{display:block;font-size:.85rem;font-weight:700;color:var(--muted);margin:12px 0 5px}input,select,button{font:inherit;border:1px solid #526e79;border-radius:7px;padding:10px;color:var(--ink);background:#20363e}input,select{width:100%}button{cursor:pointer;white-space:nowrap}button.primary{background:var(--accent);color:#10372d;border-color:var(--accent);font-weight:750}button:disabled{opacity:.45;cursor:default}input:disabled,select:disabled{opacity:.6}a{color:var(--accent)}input:focus-visible,select:focus-visible,button:focus-visible,a:focus-visible{outline:3px solid var(--accent);outline-offset:3px}.row{display:flex;align-items:end;gap:12px;flex-wrap:wrap}.row>*{flex:1}.row>button{flex:0 0 auto}.actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:16px}.split{display:grid;grid-template-columns:1fr 1fr;gap:14px}.notice{border-left:3px solid var(--gold);padding-left:14px;font-size:.9rem}.status{padding:12px 0;min-height:44px;color:var(--accent);overflow-wrap:anywhere}.status.error{color:#ffb4a9}.small{font-size:.85rem}.table-scroll{overflow:auto}table{width:100%;border-collapse:collapse;font-size:.85rem}th,td{border-bottom:1px solid var(--border);padding:11px;text-align:left;vertical-align:middle}th{color:var(--muted)}code{overflow-wrap:anywhere;font-size:.86em}.tag{border:1px solid var(--border);border-radius:20px;padding:3px 10px;font-size:.8rem;display:inline-block}.check{display:flex;align-items:center;gap:8px;font-size:.85rem;font-weight:400;margin:0}.check input{width:auto}#report-frame{width:100%;height:1000px;border:1px solid var(--border);border-radius:12px;background:var(--bg)}[hidden]{display:none!important}footer{font-size:.85rem;color:var(--muted);margin-top:28px;padding-top:18px;border-top:1px solid var(--border)}fieldset{border:0;padding:0;margin:0;min-width:0}legend{font-weight:750;padding:0}.skip{position:absolute;left:-9999px}.skip:focus{left:20px;top:20px;padding:10px;background:var(--bg);z-index:10}@media(max-width:750px){main{padding:20px 16px}.grid{grid-template-columns:1fr}.row{align-items:stretch}.row>*{flex-basis:100%}.row>button{flex:1}.split{grid-template-columns:1fr}.panel{padding:16px}}
</style></head><body><a class="skip" href="#team-controls">Skip to workspace controls</a><main>
<header><p class="eyebrow">JEFFE ULTIMATE · SHARED TEAM WORKSPACE</p><h1>Recover together.<br>Keep the evidence private.</h1><p class="muted">Manage local offline recovery jobs and review implementation progress. Workspace access follows your assigned server role.</p></header>
<section id="connection" class="panel" aria-labelledby="connection-title"><h2 id="connection-title">Connect to the workspace</h2><form id="connect-form"><div class="row"><div><label for="access-token">Access token</label><input id="access-token" type="password" autocomplete="off" spellcheck="false" placeholder="Paste the token supplied by your administrator" required></div><button type="submit" class="primary" id="connect-button">Connect</button></div></form><p class="small muted">The token is held only in this tab's memory. Reloading or disconnecting clears it. Use your administrator's HTTPS address for remote connections.</p><div id="connection-info" hidden><span id="identity" class="tag"></span><div class="actions"><button id="refresh" type="button">Refresh workspace</button><button id="disconnect" type="button">Disconnect</button><label class="check"><input id="auto-refresh" type="checkbox">Refresh every 10 seconds</label></div></div></section>
<div id="message" class="status" role="status" aria-live="polite"></div>
<div id="workspace" hidden>
<p id="viewer-note" class="notice" hidden>Your role permits viewing the workspace. An operator or administrator can upload files and run jobs.</p>
<section id="team-controls" class="grid" aria-label="Recovery controls">
<div class="panel"><h2>Import an input</h2><p class="muted small">Upload an existing hash file or wordlist. Original filenames are not sent as metadata. The server validates size and content handling.</p><form id="upload-form"><fieldset id="upload-fields"><label for="upload-kind">Input type</label><select id="upload-kind"><option value="hashes">Hash records</option><option value="wordlist">Wordlist</option></select><label for="input-file">Local file</label><input id="input-file" type="file" required><div class="actions"><button type="submit" class="primary">Import file</button></div></fieldset></form></div>
<div class="panel"><h2>Create a bounded recovery job</h2><p class="muted small">Select server-managed inputs and an installed engine. Creating a job does not start it.</p><form id="job-form"><fieldset id="job-fields"><div class="split"><div><label for="engine">Engine</label><select id="engine"><option value="john">John</option><option value="hashcat">Hashcat</option></select></div><div><label for="format">Format / mode</label><input id="format" placeholder="e.g. raw-sha256 or 1400" maxlength="128" required></div></div><label for="hash-asset">Hash input</label><select id="hash-asset" required><option value="">Import a hash file first</option></select><label for="wordlist-asset">Wordlist input</label><select id="wordlist-asset" required><option value="">Import a wordlist first</option></select><label for="runtime">Maximum runtime in seconds</label><input id="runtime" type="number" min="1" max="3600" step="1" value="30" required><div class="actions"><button type="submit" class="primary">Create job</button></div></fieldset></form></div></section>
<section class="panel" aria-labelledby="jobs-title"><h2 id="jobs-title">Jobs</h2><p class="muted small">Starting and resuming are explicit actions. Jobs with incomplete or failed recovery are not evidence of password strength.</p><div class="table-scroll"><table><thead><tr><th scope="col">Job identifier</th><th scope="col">Status</th><th scope="col">Created</th><th scope="col">Action</th></tr></thead><tbody id="jobs-body"><tr><td colspan="4">No jobs loaded.</td></tr></tbody></table></div></section>
<section class="panel"><h2>Dashboard and review catalog</h2><p class="muted small">This report is isolated from the connection controls. Refresh to update the implementation tracker and aggregate job results.</p><iframe id="report-frame" title="Sanitized workspace dashboard" sandbox="allow-scripts"></iframe></section>
</div>
<noscript><p class="notice">JavaScript is required to connect to the authenticated team API. The command-line interface remains available to local operators.</p></noscript>
<footer>The interface sends bearer credentials only in an Authorization header to this server. It does not store tokens in cookies, browser storage, links, reports, or logs. Disconnect before sharing this browser tab.</footer>
</main><script>
'use strict';
let accessToken='';let identity=null;let refreshing=false;let busy=false;let generation=0;
const el=id=>document.getElementById(id);const node=(tag,value)=>{const n=document.createElement(tag);n.textContent=value;return n;};
function message(value,error=false){el('message').textContent=value;el('message').className=error?'status error':'status';}
function canWrite(){return identity&&['operator','admin'].includes(identity.role);}
function controls(){el('upload-fields').disabled=!canWrite()||busy;el('job-fields').disabled=!canWrite()||busy;el('viewer-note').hidden=canWrite();el('refresh').disabled=busy||refreshing;for(const button of document.querySelectorAll('[data-job-action]'))button.disabled=!canWrite()||busy;}
async function request(path,options={},asText=false){if(!accessToken)throw new Error('Connect to the workspace first.');const headers=new Headers(options.headers||{});headers.set('Authorization','Bearer '+accessToken);const response=await fetch(path,{...options,headers,credentials:'omit',cache:'no-store',redirect:'error'});if(!response.ok){let detail='Request failed ('+response.status+').';try{const body=await response.json();if(body.error&&typeof body.error.message==='string')detail=body.error.message;}catch{}if(response.status===401)throw new Error('Access was rejected. Reconnect with a valid token.');if(response.status===403)throw new Error('Your role cannot perform this action. '+detail);throw new Error(detail);}return asText?response.text():response.json();}
function disconnect(){generation++;accessToken='';identity=null;el('access-token').value='';el('connect-form').hidden=false;el('connection-info').hidden=true;el('workspace').hidden=true;el('report-frame').removeAttribute('srcdoc');el('report-frame').src='about:blank';el('jobs-body').replaceChildren();el('hash-asset').replaceChildren();el('wordlist-asset').replaceChildren();el('input-file').value='';el('format').value='';el('identity').textContent='';message('Disconnected. The access token has been cleared.');}
function assetOptions(id,rows,kind){const select=el(id);const previous=select.value;select.replaceChildren();const empty=node('option','Select an imported '+(kind==='hashes'?'hash file':'wordlist'));empty.value='';select.append(empty);for(const row of rows){if(row.kind!==kind)continue;const option=node('option',String(row.id)+' · '+String(row.size??row.size_bytes??0)+' bytes');option.value=String(row.id);select.append(option);}if([...select.options].some(o=>o.value===previous))select.value=previous;}
function jobsTable(rows){const body=el('jobs-body');body.replaceChildren();for(const job of rows){const tr=document.createElement('tr');const idCell=document.createElement('td');idCell.append(node('code',String(job.id||'')));tr.append(idCell,node('td',String(job.status||'')),node('td',String(job.created_at||'')));const action=document.createElement('td');if(canWrite()&&['queued','interrupted'].includes(job.status)){const verb=job.status==='interrupted'?'resume':'run';const button=node('button',verb==='resume'?'Resume':'Start');button.type='button';button.dataset.jobAction=verb;button.disabled=busy;button.addEventListener('click',()=>jobAction(String(job.id),verb));action.append(button);}else action.append(node('span',canWrite()?'—':'View only'));tr.append(action);body.append(tr);}if(!rows.length){const tr=document.createElement('tr');const td=node('td','No jobs recorded. Import inputs and create a job to begin.');td.colSpan=4;tr.append(td);body.append(tr);}}
async function loadAssets(){const rows=[];for(let offset=0;offset<10000;offset+=1000){const batch=await request('/api/assets?limit=1000&offset='+offset);if(!Array.isArray(batch))throw new Error('The server returned an invalid asset listing.');rows.push(...batch);if(batch.length<1000)break;}return rows;}
async function refresh(){if(!accessToken||refreshing)return;const snapshot=generation;refreshing=true;controls();try{const [assets,jobs,report]=await Promise.all([loadAssets(),request('/api/jobs'),request('/api/dashboard',{},true)]);if(snapshot!==generation||!accessToken)return;assetOptions('hash-asset',Array.isArray(assets)?assets:[],'hashes');assetOptions('wordlist-asset',Array.isArray(assets)?assets:[],'wordlist');jobsTable(Array.isArray(jobs)?jobs:[]);el('report-frame').srcdoc=report;}finally{refreshing=false;controls();}}
async function action(work){if(busy)return;busy=true;controls();const snapshot=generation;try{const result=await work();if(snapshot!==generation)return;message(result);await refresh();}catch(error){if(snapshot===generation)message(error.message||'The action could not be completed.',true);}finally{busy=false;controls();}}
async function jobAction(id,verb){await action(async()=>{const result=await request('/api/jobs/'+encodeURIComponent(id)+'/'+verb,{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});return 'Job '+String(result.id||id)+' scheduled. Refresh to follow its status.';});}
el('connect-form').addEventListener('submit',async event=>{event.preventDefault();if(busy)return;accessToken=el('access-token').value.trim();el('access-token').value='';generation++;const snapshot=generation;busy=true;el('connect-button').disabled=true;try{const who=await request('/api/me');if(snapshot!==generation)return;identity=who;el('identity').textContent=String(identity.name||'Team member')+' · '+String(identity.role||'viewer');el('connect-form').hidden=true;el('connection-info').hidden=false;el('workspace').hidden=false;message('Connected. Loading the workspace.');await refresh();if(snapshot===generation)message('Workspace refreshed.');}catch(error){if(snapshot===generation){disconnect();message(error.message||'Connection failed.',true);}}finally{busy=false;el('connect-button').disabled=false;controls();}});
el('disconnect').addEventListener('click',disconnect);el('refresh').addEventListener('click',()=>refresh().then(()=>message('Workspace refreshed.')).catch(error=>message(error.message,true)));
el('upload-form').addEventListener('submit',event=>{event.preventDefault();const file=el('input-file').files[0];if(!file){message('Select a local file first.',true);return;}action(async()=>{const asset=await request('/api/assets?kind='+encodeURIComponent(el('upload-kind').value),{method:'POST',headers:{'Content-Type':'application/octet-stream'},body:file});el('input-file').value='';return 'Imported asset '+String(asset.id)+'.';});});
el('job-form').addEventListener('submit',event=>{event.preventDefault();const spec={engine:el('engine').value,format:el('format').value.trim(),input_id:el('hash-asset').value,wordlist_id:el('wordlist-asset').value,runtime_seconds:Number(el('runtime').value)};action(async()=>{const job=await request('/api/jobs',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(spec)});return 'Created job '+String(job.id)+'. Select Start when ready.';});});
setInterval(()=>{if(accessToken&&el('auto-refresh').checked&&!busy)refresh().catch(error=>message(error.message,true));},10000);
</script></body></html>'''


_TEMPLATE = '''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'none'; img-src 'none'; base-uri 'none'; form-action 'none'">
<title>JEFFE Ultimate — local workbench</title>
<style>
:root{color-scheme:dark;--bg:#10191e;--panel:#19272e;--ink:#ecf4f2;--muted:#aec3ca;--accent:#69e5c0;--border:#34505b;--gold:#eccc81}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.6 system-ui,sans-serif}main{max-width:1240px;margin:auto;padding:36px 24px 70px}a{color:var(--accent)}h1{font-size:clamp(2.2rem,5vw,4.2rem);line-height:1.05;letter-spacing:-.04em;margin:20px 0}h2{font-size:1.65rem;margin:0 0 12px}p{max-width:950px}header{margin-bottom:30px}.eyebrow{font-size:.75rem;color:var(--accent);font-weight:800;letter-spacing:.16em}.muted,small{color:var(--muted)}nav{display:flex;gap:24px;flex-wrap:wrap;margin-top:24px}.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:30px 0}.stat,.panel,.card{border:1px solid var(--border);background:var(--panel);border-radius:14px;padding:20px}.stat strong{display:block;font-size:2rem;color:var(--ink)}.stat span{font-size:.85rem;color:var(--muted)}section{margin-top:36px}.note{border-left:3px solid var(--gold);padding-left:16px}.toolbar{display:grid;grid-template-columns:2fr 1.5fr 1fr;gap:12px;padding:15px;background:#142229;border:1px solid var(--border);border-radius:12px}label{font-size:.8rem;font-weight:700;color:var(--muted)}input,select,button{font:inherit;border-radius:6px;border:1px solid #526e79;background:#20363e;color:var(--ink);padding:10px;width:100%}input:focus-visible,select:focus-visible,button:focus-visible,a:focus-visible,summary:focus-visible{outline:3px solid var(--accent);outline-offset:3px}button{width:auto;cursor:pointer}button:disabled{opacity:.45;cursor:default}.cards{display:grid;grid-template-columns:1fr 1fr;gap:13px;margin:16px 0}.card p{margin:10px 0}.card h3{font-size:1rem;margin:0}.card .topline{display:flex;justify-content:space-between;gap:12px;margin-bottom:10px}.card .id{color:var(--accent);font-weight:800}.tag{font-size:.75rem;border:1px solid var(--border);border-radius:20px;padding:2px 9px;display:inline-block;white-space:nowrap}.tag.implemented{color:var(--accent)}.tag.partial,.tag.needs-review{color:var(--gold)}.category{font-size:.78rem;color:var(--muted)}.pagination{display:flex;align-items:center;justify-content:space-between;gap:12px}.table-scroll{overflow:auto}table{width:100%;border-collapse:collapse;font-size:.9rem}td,th{padding:12px;text-align:left;border-bottom:1px solid var(--border);vertical-align:top}th{color:var(--muted)}code{overflow-wrap:anywhere;font-size:.88em}details{margin-top:14px}summary{cursor:pointer;color:var(--muted)}li{margin:8px 0}.source-links{display:flex;gap:14px;flex-wrap:wrap;font-size:.8rem;margin-top:12px}.empty{padding:24px;border:1px dashed var(--border);border-radius:10px;color:var(--muted)}footer{margin-top:40px;border-top:1px solid var(--border);padding-top:20px;font-size:.88rem;color:var(--muted)}.skip{position:absolute;left:-9999px}.skip:focus{left:20px;top:20px;background:var(--bg);padding:10px;z-index:10}.small{font-size:.84rem}ul{padding-left:23px}@media(max-width:750px){main{padding:24px 16px}.stats{grid-template-columns:1fr 1fr}.cards{grid-template-columns:1fr}.toolbar{grid-template-columns:1fr}.stat{padding:14px}}@media(prefers-reduced-motion:reduce){*{scroll-behavior:auto!important}}@media print{body{background:white;color:black}.panel,.card,.stat{background:white;color:black;break-inside:avoid}.toolbar,.pagination,nav{display:none}.cards{display:block}.card{margin-bottom:12px}.muted,small,.category,footer{color:#444}a{color:#155640}}
</style></head><body><a href="#backlog" class="skip">Skip to implementation tracker</a><main>
<header><p class="eyebrow">JEFFE ULTIMATE · LOCAL SNAPSHOT</p><h1>Your recovery<br>workbench.</h1><p class="muted">Project health, job outcomes, reviewed sources, and an honest implementation tracker. This snapshot contains aggregate results and job identifiers; sensitive inputs and engine output remain in the private workspace.</p><nav aria-label="Dashboard sections"><a href="#jobs">Jobs</a><a href="#backlog">Implementation tracker</a><a href="#integrations">Reviewed projects</a></nav></header>
<div class="stats" aria-label="Workspace overview"><div class="stat"><strong>__ASSETS__</strong><span>assets · __BYTES__ bytes</span></div><div class="stat"><strong>__JOBS__</strong><span>jobs in workspace</span></div><div class="stat"><strong>__IMPLEMENTED__ / __IDEAS__</strong><span>ideas marked implemented · __PARTIAL__ partial</span></div><div class="stat"><strong>__PROJECTS__</strong><span>catalog entries</span></div></div>
<p class="note small">A reviewed repository is not automatically an installed integration. “Reference-only” entries provide research context. “Partial” and “planned” items are not completed features. This static snapshot does not start jobs or run plugins.</p>
<section id="jobs" class="panel"><h2>Job history</h2><p class="muted small">Statuses describe recorded engine outcomes. Exhausted work does not prove a password is secure. This table may show a limited recent-job window even when the total above is larger.</p><div class="table-scroll"><table><thead><tr><th scope="col">Job identifier</th><th scope="col">Status</th><th scope="col">Created</th></tr></thead><tbody>__JOB_FALLBACK__</tbody></table></div></section>
<section id="backlog"><h2>Implementation tracker</h2><p class="muted small">Search by exact idea number or text. Priority and effort are planning estimates; status records implementation progress.</p><div class="toolbar"><label for="idea-search">Search ideas<input type="search" id="idea-search" placeholder="checkpoint, GPU, or an idea number"></label><label for="idea-category">Category<select id="idea-category"><option value="">All categories</option></select></label><label for="idea-status">Status<select id="idea-status"><option value="">All statuses</option></select></label></div><p id="idea-count" role="status" aria-live="polite"></p><div id="ideas" class="cards"></div><div class="pagination"><button id="previous" type="button">Previous 50</button><span id="page-number"></span><button id="next" type="button">Next 50</button></div></section>
<section id="integrations"><h2>Reviewed projects</h2><p class="muted small">Descriptions are source claims, not verified performance guarantees. Review findings and decisions explain the intended relationship to this workbench.</p><div class="toolbar"><label for="project-search">Search projects<input type="search" id="project-search" placeholder="project, license, or review finding"></label><label for="project-decision">Decision<select id="project-decision"><option value="">All decisions</option></select></label><div></div></div><p id="project-count" role="status" aria-live="polite"></p><div id="projects" class="cards"></div></section>
<noscript><p class="note">JavaScript is required for the searchable tracker and project catalog. Job history and totals remain visible. Use the companion JSON or report for the complete tracker.</p></noscript>
<footer><p>Generated locally. Search stays in this file; there are no analytics, external fonts, remote scripts, or background network requests. Source links open external websites only when selected. Regenerate the snapshot after changing workspace state.</p></footer>
</main><script type="application/json" id="dashboard-data">__DATA__</script><script>
'use strict';
const data=JSON.parse(document.getElementById('dashboard-data').textContent);
const byId=id=>document.getElementById(id);
const text=(tag,value,className)=>{const el=document.createElement(tag);el.textContent=value;if(className)el.className=className;return el;};
const fill=(id,values)=>{for(const value of [...new Set(values)].sort()){const option=text('option',value);option.value=value;byId(id).append(option);}};
fill('idea-category',data.backlog.map(r=>r.category));fill('idea-status',data.backlog.map(r=>r.status));fill('project-decision',data.integrations.map(r=>r.decision));
let page=0;const pageSize=50;
function renderIdeas(){const q=byId('idea-search').value.trim().toLocaleLowerCase();const category=byId('idea-category').value;const status=byId('idea-status').value;const filtered=data.backlog.filter(r=>(!category||r.category===category)&&(!status||r.status===status)&&(!q||(/^\\d+$/.test(q)?Number(r.id)===Number(q):(r.idea+' '+r.category).toLocaleLowerCase().includes(q))));const pages=Math.max(1,Math.ceil(filtered.length/pageSize));page=Math.max(0,Math.min(page,pages-1));const container=byId('ideas');container.replaceChildren();for(const row of filtered.slice(page*pageSize,(page+1)*pageSize)){const card=document.createElement('article');card.className='card';const top=document.createElement('div');top.className='topline';top.append(text('span','#'+row.id,'id'),text('span',row.status,'tag '+(row.status==='implemented'?'implemented':row.status==='partial'?'partial':'')));card.append(top,text('div',row.category,'category'),text('p',row.idea),text('div',row.priority+' · Effort '+row.effort,'category'));container.append(card);}if(!filtered.length)container.append(text('p','No ideas match these filters.','empty'));byId('idea-count').textContent=filtered.length+' of '+data.backlog.length+' ideas'+(filtered.length?' · showing '+(page*pageSize+1)+'–'+Math.min((page+1)*pageSize,filtered.length):'');byId('page-number').textContent='Page '+(page+1)+' of '+pages;byId('previous').disabled=page===0;byId('next').disabled=page>=pages-1;}
function link(url,label){const el=text('a',label);el.href=url;el.target='_blank';el.rel='noopener noreferrer';return el;}
function renderProjects(){const q=byId('project-search').value.trim().toLocaleLowerCase();const decision=byId('project-decision').value;const filtered=data.integrations.filter(r=>(!decision||r.decision===decision)&&(!q||(r.repo+' '+r.description+' '+r.reason+' '+r.license+' '+r.observations.join(' ')).toLocaleLowerCase().includes(q)));const container=byId('projects');container.replaceChildren();for(const row of filtered){const card=document.createElement('article');card.className='card';const top=document.createElement('div');top.className='topline';const title=text('h3','');title.append(row.url?link(row.url,row.repo||row.url):text('span',row.repo||'Source unavailable'));top.append(title,text('span',row.decision,'tag '+(row.decision==='needs-review'?'needs-review':'')));card.append(top);if(row.reason)card.append(text('p',row.reason));if(row.license)card.append(text('div','License: '+row.license,'category'));if(row.head_sha)card.append(text('div','Inspected revision: '+row.head_sha,'category'));const details=document.createElement('details');details.append(text('summary','Review evidence and source description'));if(row.description)details.append(text('p','Upstream description: '+row.description,'small'));const list=document.createElement('ul');for(const observation of row.observations)list.append(text('li',observation));details.append(list);const sources=document.createElement('div');sources.className='source-links';row.sources.forEach((url,index)=>sources.append(link(url,'Source '+(index+1))));details.append(sources);card.append(details);container.append(card);}if(!filtered.length)container.append(text('p','No projects match these filters.','empty'));byId('project-count').textContent=filtered.length+' of '+data.integrations.length+' catalog entries';}
for(const id of ['idea-search','idea-category','idea-status'])byId(id).addEventListener('input',()=>{page=0;renderIdeas();});for(const id of ['project-search','project-decision'])byId(id).addEventListener('input',renderProjects);byId('previous').addEventListener('click',()=>{page--;renderIdeas();byId('backlog').scrollIntoView();});byId('next').addEventListener('click',()=>{page++;renderIdeas();byId('backlog').scrollIntoView();});renderIdeas();renderProjects();
</script></body></html>
'''
