# Prod bring-up runbook — Cloud Infrastructure web host

Copy the working dev setup (HTTPS, landing page, URL resolver, zone-sharing app
behind nginx) onto the prod instance, then add Entra SSO for zone-sharing.

## Environment facts

| Item             | Dev                                  | Prod                                 |
|------------------|--------------------------------------|--------------------------------------|
| Instance id      | `i-09daf85c55e1ab7f7`                | `i-048132bacaa7bdbea`                |
| Name tag         | `CloudInfraWebDev`                   | `CloudInfraWebProd`                  |
| Private IP       | `10.160.40.160`                      | `10.160.40.179`                      |
| FQDN             | `cloudinfraweb-dev.np.aws.csaa.pri`  | `cloudinfraweb.np.aws.csaa.pri`      |
| AMI              | (older)                              | `ami-08785e7ce8b3b39e6` (CSAA AL2023 base, 2026-11-02) |
| CFN stack        | —                                    | `cloudinfraweb-prod`                 |
| Shared by both   | account 344327960130, us-west-2, t3.medium, subnet-002fbae03403af676, sg-088ce971fce0eaaa2, CloudInfraEc2Role, IMDSv2, SSM access only |

`i-0107991ec9add020e` (Name `CloudInfraWeb`, 10.160.40.129, `ec2Builder` stack)
is an older box that nothing points at any more. It is neither dev nor prod.

Profile for AWS CLI: `PSAdminRole_1-344327960130`
(set `$env:AWS_CA_BUNDLE = "C:\Users\g05dows\.aws\ca-bundle.crt"` first).

---

## Step 1 — Instance  (DONE)

Stack `cloudinfraweb-prod` from `infra/cloudinfraweb-ec2.yaml`. SSM agent online.

## Step 2 — DNS  (DONE)

`cloudinfraweb.np.aws.csaa.pri` → `10.160.40.179`.

---

## Step 3 — Packages

Open a Session Manager shell to `i-048132bacaa7bdbea`:

```bash
sudo dnf install -y nginx git python3-pip
sudo systemctl enable nginx
```

## Step 4 — TLS certificate

Dev's cert is at `/opt/managedcerts/server.crt` + `server.key`. Prod needs a cert
whose SAN includes **`cloudinfraweb.np.aws.csaa.pri`**, at the same paths.

```bash
sudo ls -l /opt/managedcerts/
sudo openssl x509 -in /opt/managedcerts/server.crt -noout -subject -enddate -ext subjectAltName
```

If the files are missing or the SAN doesn't list the prod name, request the cert
the same way dev's was obtained. Until it's installed, run prod on HTTP with
`nginx/cloud-infra-http.conf` (Step 6). The HTTPS config won't start without
these files.

**Status:** prod has no cert yet (`/opt/managedcerts` doesn't exist). Running
HTTP-only for now.

## Step 5 — Clone the repo and install the apps

```bash
sudo git clone https://github.com/ddowsett/cloud-infra-automation /opt/cloud-infra-automation
sudo git config --global --add safe.directory /opt/cloud-infra-automation

cd /opt/cloud-infra-automation/url-lookup   && sudo bash deploy/install.sh
cd /opt/cloud-infra-automation/zone-sharing && sudo bash deploy/install.sh
```

Each installer creates its service user, venv and systemd unit, then starts the
service. Both end with a local health check (`127.0.0.1:8000/healthz`,
`127.0.0.1:8080/`).

> **Zone-sharing has no login until Step 8.** It makes real Route 53 changes.
> To keep it off on prod until SSO is live:
> `sudo systemctl disable --now zone-sharing`
> (The landing page's Zone Sharing link then returns 502, which is expected.)

## Step 6 — nginx

Clear any `server { }` blocks the stock `nginx.conf` defines. On dev, a leftover
default TLS block caused the "Welcome to nginx" page and a startup error.

```bash
grep -n "server {" /etc/nginx/nginx.conf
```

If that prints any line that isn't commented out (`#`), back the file up
(`sudo cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak`) and delete those
`server { ... }` blocks. Keep `include /etc/nginx/conf.d/*.conf;` and the closing
`}` of the `http` block.

Then install the nginx config from the repo.

**No cert yet: HTTP only**
```bash
sudo cp /opt/cloud-infra-automation/nginx/cloud-infra-http.conf /etc/nginx/conf.d/cloud-infra.conf
sudo nginx -t && sudo systemctl restart nginx
```

**Cert installed: HTTPS** (same file dev uses; port 80 redirects to HTTPS)
```bash
sudo cp /opt/cloud-infra-automation/nginx/cloud-infra-interim.conf /etc/nginx/conf.d/cloud-infra.conf
sudo nginx -t && sudo systemctl reload nginx
```

## Step 7 — Verify

HTTP only:
```bash
curl -s -o /dev/null -w "landing %{http_code}\n"    http://cloudinfraweb.np.aws.csaa.pri/
curl -s -o /dev/null -w "url-lookup %{http_code}\n" http://cloudinfraweb.np.aws.csaa.pri/url-lookup/
```

After the cert (HTTPS), use `https://`. No `-k`, so this also proves the cert is trusted.

Both should print `200`. If
the instance can't resolve the name, run `sudo resolvectl flush-caches` (same as
dev). Then in a browser, resolve `cdh-e2e.private.np.aws.csaa.pri` and an S3
URL such as `csaa-ds-releases.s3.amazonaws.com`.

If a page returns 502 and `journalctl -u url-lookup` looks healthy, check
SELinux: `getenforce`. If `Enforcing`, run
`sudo setsebool -P httpd_can_network_connect 1`.

---

## Step 8 — Entra SSO for zone-sharing only  (waiting on Entra team)

Access model: landing page and `/url-lookup/` stay open to everyone on the
network. `/zone-sharing/` requires Entra sign-in and membership of
`GrpIT_CloudInfrastructureTeam`. The Entra app registration
(`CloudInfraZoneShare`) lists both dev and prod callback URLs, so one
registration covers both servers.

When the tenant ID, client ID, group object ID and client secret arrive, the
repo's `nginx/cloud-infra.conf` and `auth/oauth2-proxy.cfg` get updated for this
model and installed per `auth/README.md`. Then:

```bash
sudo systemctl enable --now zone-sharing
```

| User                                  | /url-lookup/ | /zone-sharing/ |
|---------------------------------------|--------------|----------------|
| anyone on the network                 | allow        | blocked at Microsoft sign-in |
| GrpIT_CloudInfrastructureTeam member  | allow        | allow          |

---

## Rollback

- Stopping `nginx`, `url-lookup` or `zone-sharing` takes prod offline without
  touching dev.
- To remove the instance: delete the `cloudinfraweb-prod` stack.
- DNS is the only shared change: repoint `cloudinfraweb.np.aws.csaa.pri` to back out.
