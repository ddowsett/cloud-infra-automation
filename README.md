# cloud-infra-automation

Cloud Infrastructure team automation, co-hosted on the EC2 web server
`i-09daf85c55e1ab7f7` (dev) / prod in account **344327960130**. Two web apps run
as independent local services behind a single **nginx** reverse proxy, separated
by URL path:

| Path | App | Backend | Purpose |
|------|-----|---------|---------|
| `/url-lookup/` | `url-lookup/` (FastAPI) | 127.0.0.1:8000 | Resolve a URL/hostname to its AWS account + resource |
| `/zone-sharing/` | `zone-sharing/` (Flask) | 127.0.0.1:8080 | Cross-account Route 53 private hosted zone sharing |

Both bind to **loopback only**; nginx is the sole entry point and routes by path
(stripping the prefix so each app serves from `/`).

## Layout

```
cloud-infra-automation/
├── nginx/cloud-infra.conf         reverse-proxy path routing (both apps)
├── iam/                           CloudFormation for shared + spoke IAM + audit table
│   ├── CloudInfraEc2Role-tooling.yaml          instance role (344327960130)
│   ├── CsaaInfraResolverReadRole-stackset.yaml read-only Route53 spoke role (org-wide)
│   ├── CsaaRoute53ZoneSharingRole-stackset.yaml zone-sharing spoke role (org-wide)
│   └── csaa-url-resolver-table.yaml            audit DynamoDB table (344327960130)
├── url-lookup/                    FastAPI resolver app
│   ├── app.py resolver.py audit.py requirements.txt
│   └── deploy/ (url-lookup.service, install.sh)
└── zone-sharing/                  Flask zone-sharing app
    ├── ShareHostedZoneAutomation.py requirements.txt
    └── deploy/ (zone-sharing.service, install.sh)
```

## Shared IAM (account 344327960130 + org-wide)

The single instance role **`CloudInfraEc2Role`** serves BOTH apps:
- Assumes `CsaaRoute53ZoneSharingRole` (zone sharing) and `CsaaInfraResolverReadRole`
  (resolver reads) in any account.
- Reads the org Config aggregator (resolver zone discovery + ENI attribution).
- Reads Route 53 locally; writes audit records to `csaa-url-resolver`.
It replaced the former full-IAM `Cloud9Role` on the instance.

Deploy status: instance role, both spoke-role StackSets, and the audit table are
deployed. See `iam/` templates for details.

## Deploy the apps (per app, via SSM on the instance)

Clone/pull this repo on the instance, then run each app's installer:

```
# URL lookup
cd cloud-infra-automation/url-lookup && sudo bash deploy/install.sh
# Zone sharing
cd cloud-infra-automation/zone-sharing && sudo bash deploy/install.sh
```

Then install the reverse proxy:

```
sudo dnf install -y nginx
sudo cp cloud-infra-automation/nginx/cloud-infra.conf /etc/nginx/conf.d/
sudo nginx -t && sudo systemctl enable --now nginx && sudo systemctl reload nginx
```

## Acceptance test (URL lookup)

Direct (pre-nginx):
```
curl -s -X POST http://127.0.0.1:8000/api/resolve \
  -H 'Content-Type: application/json' \
  -d '{"url":"progress-p.private.np.aws.csaa.pri"}' | python3 -m json.tool
```
Through nginx:
```
curl -s -X POST http://127.0.0.1/url-lookup/api/resolve \
  -H 'Content-Type: application/json' \
  -d '{"url":"progress-p.private.np.aws.csaa.pri"}' | python3 -m json.tool
```
Expected: resolves to the `kh-test-progress` internal ELB in account
608859702194, and writes an audit item to the `csaa-url-resolver` DynamoDB table.

## Notes / TODO

- **Auth**: `url-lookup` records `requester` as `unknown` until fronted by SSO/an
  ALB injecting the user (the app honors `x-amzn-oidc-identity`/`x-forwarded-user`).
  Add auth before broad ("all users") exposure.
- **IMDSv2**: ensure the instance enforces `HttpTokens=required`.
- **zone-sharing** serves `index.html` from `/var/www/html`; confirm its form
  action is prefix-safe when reached via `/zone-sharing/` (nginx strips the prefix).
- **TLS**: this config listens on :80. Add a TLS server block / cert for prod.
