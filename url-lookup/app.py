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
    .err { color: #c5221f; }
    code { background:#f6f8fa; padding:.05rem .3rem; border-radius:3px; font-size:.85rem; }
    pre { background: #f6f8fa; padding: .8rem; border-radius: 6px; overflow: auto; max-width: 980px; }
    .tag { display:inline-block; background:#eef3fd; color:#1662d4; border-radius: 4px; padding: .05rem .4rem; margin:.1rem; font-size:.85rem;}
    .match { padding:.5rem 0; }
    .match + .match { border-top:1px solid #eee; margin-top:.5rem; }
    .match .title { margin-bottom:.35rem; }
    .match .attr { display:block; line-height:1.5; }
    .match .attr .lbl { color:#555; display:inline-block; min-width:120px; }
    .match .tags { margin:.15rem 0 0 1.2rem; font-size:.85rem; line-height:1.5; overflow-wrap:anywhere; }
    .match .tags .tk { color:#555; }
    .hop { display:inline-block; min-width:1.3rem; height:1.3rem; line-height:1.3rem; text-align:center;
           background:#1662d4; color:#fff; border-radius:50%; font-size:.78rem; font-weight:600; margin-right:.4rem; }
    .site-header { margin-bottom: 1.2rem; padding-bottom: .8rem; border-bottom: 1px solid #eee; }
    .logo { height: 44px; width: auto; display: block; }
  </style>
</head>
<body>
  <div class="site-header"><img class="logo" alt="CSAA Insurance Group, a AAA Insurer" src="data:image/png;base64,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"/></div>
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
      if (d.ip_locations && d.ip_locations.length) {
        rows += `<tr><th>Network location</th><td>` +
          d.ip_locations.map(l => `<div><b>${esc(l.location)}</b>` +
            (l.ip ? ` <span class=muted>(${esc(l.ip)}${l.cidr ? ', '+esc(l.cidr) : ''})</span>` : '') +
            `</div>`).join('') +
          `</td></tr>`;
      }
      if (d.trace && d.trace.length) {
        let t = '';
        d.trace.forEach(tr => {
          let hop = 0;
          const num = () => `<span class=hop>${++hop}</span>`;
          t += `<div style="margin-bottom:.6rem">`;
          t += `${num()}<b>${esc(tr.load_balancer)}</b> <span class=muted>(account ${esc(tr.lb_account)} · ${esc(tr.lb_region)})</span>`;
          (tr.steps || []).forEach(s => {
            if (s.error) { t += `<div class=err style="margin-left:1rem">${esc(s.step)}: ${esc(s.error)}</div>`; return; }
            t += `<div style="margin-left:1rem;margin-top:.6rem">${num()}target group <b>${esc(s.name)}</b> ` +
                 `<span class=muted>(${esc(s.target_type)} ${esc(s.protocol)}:${esc(s.port)})</span></div>`;
            (s.targets || []).forEach(tg => {
              t += `<div style="margin-left:2.7rem" class=muted>target ${esc(tg.target)} — ${esc(tg.health)}</div>`;
            });
            (s.destinations || []).forEach(dest => {
              t += `<div style="margin-left:1rem;margin-top:.6rem">${num()}via <code>${esc(dest.via_vpc_endpoint)}</code>` +
                   (dest.service ? ` <span class=muted>(${esc(dest.service)})</span>` : '') + `</div>`;
              const er = dest.endpoint_resource;
              if (er) {
                t += `<div style="margin-left:1rem;margin-top:.6rem">${num()}<span class="tag">${esc(er.resource_type)}</span> <b>${esc(er.name)}</b></div>`;
                t += `<div style="margin-left:2.7rem" class=muted>` +
                     `account ${esc(er.account_id)} · ${esc(er.region)}` +
                     (er.owner_contact ? ` · owner ${esc(er.owner_contact)}` : '') +
                     (er.cost_center ? ` · cost-center ${esc(er.cost_center)}` : '') +
                     `</div>`;
              } else if (dest.terminus) {
                t += `<div style="margin-left:1rem;margin-top:.6rem">${num()}<span class="tag">${esc(dest.terminus)}</span></div>`;
              }
            });
          });
          t += `</div>`;
        });
        rows += `<tr><th>Traffic path (deep trace)</th><td>${t}</td></tr>`;
      }
      // When a deep trace is present, it is the primary narrative (it names the
      // load balancer and ends at the real endpoint), so skip the redundant
      // Resource match(es) table to keep the result readable.
      if (d.matches && d.matches.length && !(d.trace && d.trace.length)) {
        const attr = (label, val) => (val==null || val==='') ? '' :
          `<span class=attr><span class=lbl>${esc(label)}</span>${esc(val)}</span>`;
        // All resource tags (e.g. S3 bucket tags), one "key: value" per line.
        const tagsBlock = (tags) => {
          const keys = tags ? Object.keys(tags) : [];
          if (!keys.length) return '';
          return `<span class=attr><span class=lbl>Tags:</span></span>` +
            `<div class=tags>` + keys.map(k =>
              `<div><span class=tk>${esc(k)}</span>: ${esc(tags[k])}</div>`).join('') + `</div>`;
        };
        rows += `<tr><th>Resource match(es)</th><td>` +
          d.matches.map(m => `<div class=match>` +
            `<div class=title><span class="tag">${esc(m.resource_type||'?')}</span> ` +
            `<b>${esc(m.workload_hint||m.resource_id||'')}</b></div>` +
            attr('AWS account:', m.account_id) +
            attr('Region:', m.region) +
            attr('Resource:', m.resource_id) +
            attr('Private IP:', m.private_ip) +
            attr('Owner:', m.owner_contact) +
            attr('Cost center:', m.cost_center) +
            tagsBlock(m.tags) +
            `</div>`).join('') +
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
