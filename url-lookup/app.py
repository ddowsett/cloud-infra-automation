"""
URL-to-Infrastructure Resolver -- web app.

FastAPI service that wraps the resolver engine and records every lookup to the
csaa-url-resolver DynamoDB audit table. Runs on its own port (default 8000) so
it coexists with the zone-sharing Flask app (port 8080) on the same instance.

Endpoints:
  GET  /            -> minimal HTML UI (input box + results)
  GET  /healthz     -> health check
  POST /api/resolve -> JSON: { "url": "..." } -> resolution result
  GET  /api/resolve?url=... -> same, convenience for links

Credentials: default chain (the CloudInfraEc2Role instance profile on EC2).
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from resolver import InfraResolver
from audit import AuditLogger

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("url-infra-resolver.app")

app = FastAPI(title="CSAA URL Infrastructure Resolver", version="1.0")

# Instantiate once (clients/inventory cache are reused across requests).
_resolver = InfraResolver()
_audit = AuditLogger()


class ResolveRequest(BaseModel):
    url: str


def _requester_from_request(request: Request) -> tuple[Optional[str], Optional[str]]:
    """Best-effort requester identity + source IP.

    'requester' is populated from an auth header if the app is fronted by SSO/an
    ALB that injects the authenticated user (e.g. x-amzn-oidc-identity or a
    reverse-proxy header). Until then it will be None (recorded as 'unknown').
    """
    src_ip = request.client.host if request.client else None
    # Honor common proxy / ALB-auth headers when present.
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        src_ip = fwd.split(",")[0].strip()
    requester = (
        request.headers.get("x-amzn-oidc-identity")
        or request.headers.get("x-forwarded-user")
        or request.headers.get("remote-user")
    )
    return requester, src_ip


def _do_resolve(url: str, request: Request) -> dict:
    result = _resolver.resolve(url).to_dict()
    requester, src_ip = _requester_from_request(request)
    lookup_id = _audit.record(
        url=url,
        hostname=result.get("hostname", ""),
        result=result,
        requester=requester,
        source_ip=src_ip,
    )
    result["lookup_id"] = lookup_id
    return result


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.post("/api/resolve")
def api_resolve_post(body: ResolveRequest, request: Request):
    if not body.url or not body.url.strip():
        return JSONResponse({"error": "url is required"}, status_code=400)
    return _do_resolve(body.url.strip(), request)


@app.get("/api/resolve")
def api_resolve_get(url: str, request: Request):
    if not url or not url.strip():
        return JSONResponse({"error": "url is required"}, status_code=400)
    return _do_resolve(url.strip(), request)


INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>CSAA URL Infrastructure Resolver</title>
  <style>
    body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem; color: #1a1a1a; }
    h1 { font-size: 1.3rem; }
    .row { display: flex; gap: .5rem; max-width: 780px; }
    input[type=text] { flex: 1; padding: .6rem .7rem; font-size: 1rem; border: 1px solid #ccc; border-radius: 6px; }
    button { padding: .6rem 1.1rem; font-size: 1rem; border: 0; border-radius: 6px; background: #1662d4; color: #fff; cursor: pointer; }
    button:disabled { background: #9bb7e8; }
    table { border-collapse: collapse; margin-top: 1.2rem; width: 100%; max-width: 980px; }
    th, td { text-align: left; padding: .4rem .6rem; border-bottom: 1px solid #eee; font-size: .92rem; vertical-align: top; }
    th { width: 200px; color: #555; }
    .muted { color: #777; }
    pre { background: #f6f8fa; padding: .8rem; border-radius: 6px; overflow: auto; max-width: 980px; }
    .tag { display:inline-block; background:#eef3fd; color:#1662d4; border-radius: 4px; padding: .05rem .4rem; margin:.1rem; font-size:.85rem;}
  </style>
</head>
<body>
  <h1>URL &rarr; Infrastructure Resolver</h1>
  <p class="muted">Enter an internal URL/hostname to find which AWS account and resource it resolves to.</p>
  <div class="row">
    <input id="url" type="text" placeholder="progress-p.private.np.aws.csaa.pri" autofocus />
    <button id="go">Resolve</button>
  </div>
  <div id="out"></div>

  <script>
    const $ = (id) => document.getElementById(id);
    async function resolve() {
      const url = $('url').value.trim();
      if (!url) return;
      $('go').disabled = true; $('out').innerHTML = '<p class="muted">Resolving…</p>';
      try {
        const r = await fetch('api/resolve', {
          method: 'POST', headers: {'Content-Type':'application/json'},
          body: JSON.stringify({url})
        });
        const d = await r.json();
        render(d);
      } catch (e) {
        $('out').innerHTML = '<p style="color:#c00">Error: ' + e + '</p>';
      } finally { $('go').disabled = false; }
    }
    function esc(s){ return (s==null?'':String(s)).replace(/[&<>]/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }
    function render(d) {
      let rows = '';
      rows += `<tr><th>Hostname</th><td>${esc(d.hostname)}</td></tr>`;
      rows += `<tr><th>Resolved IPs</th><td>${(d.resolved_ips||[]).map(esc).join(', ') || '<span class=muted>none (private DNS / off-VPC)</span>'}</td></tr>`;
      if (d.zone_records && d.zone_records.length) {
        rows += `<tr><th>Route 53 record(s)</th><td>` +
          d.zone_records.map(z => `${esc(z.record_type)} in <b>${esc(z.zone_name)}</b> (acct ${esc(z.zone_account_id)})` +
            (z.alias_target ? ` &rarr; <code>${esc(z.alias_target)}</code>` : '') +
            (z.values && z.values.length ? ` = ${z.values.map(esc).join(', ')}` : '')).join('<br/>') +
          `</td></tr>`;
      }
      if (d.split_horizon) rows += `<tr><th>Split-horizon</th><td>Record found in multiple accounts</td></tr>`;
      if (d.matches && d.matches.length) {
        rows += `<tr><th>Resource match(es)</th><td>` +
          d.matches.map(m => `<div><span class="tag">${esc(m.resource_type||'?')}</span> ` +
            `<b>${esc(m.workload_hint||m.resource_id||'')}</b><br/>` +
            `<span class=muted>account ${esc(m.account_id)} · ${esc(m.region)} · ${esc(m.resource_id)}` +
            (m.private_ip? ' · '+esc(m.private_ip):'') + `</span></div>`).join('<br/>') +
          `</td></tr>`;
      }
      if (d.notes && d.notes.length) rows += `<tr><th>Notes</th><td class=muted>${d.notes.map(esc).join('<br/>')}</td></tr>`;
      rows += `<tr><th>Audit lookup id</th><td class=muted>${esc(d.lookup_id)}</td></tr>`;
      $('out').innerHTML = `<table>${rows}</table>`;
    }
    $('go').addEventListener('click', resolve);
    $('url').addEventListener('keydown', e => { if (e.key === 'Enter') resolve(); });
  </script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
def index():
    return INDEX_HTML
