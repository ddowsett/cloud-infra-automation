#!/usr/bin/env bash
#
# Install / update the URL Lookup resolver (FastAPI) on Amazon Linux 2023.
# Run from the url-lookup/ directory of the cloned repo, via SSM or a session.
# Idempotent. Runs on 127.0.0.1:8000 behind nginx at /url-lookup/.
# Does NOT touch the zone-sharing app.
#
set -euo pipefail

APP_DIR=/opt/cloud-infra-automation/url-lookup
SVC=url-lookup
SVC_USER=urllookup

echo "== 1. Service user =="
if ! id "$SVC_USER" >/dev/null 2>&1; then
  sudo useradd --system --no-create-home --shell /sbin/nologin "$SVC_USER"
fi

echo "== 2. App directory =="
sudo mkdir -p "$APP_DIR"

echo "== 3. Copy application files =="
for f in app.py resolver.py audit.py requirements.txt; do
  if [ ! -f "./$f" ]; then
    echo "ERROR: missing $f in $(pwd). Run from the url-lookup/ dir." >&2
    exit 1
  fi
  sudo cp "./$f" "$APP_DIR/$f"
done

echo "== 4. Python venv + deps =="
if [ ! -d "$APP_DIR/venv" ]; then
  sudo python3 -m venv "$APP_DIR/venv"
fi
sudo "$APP_DIR/venv/bin/pip" install --upgrade pip
sudo "$APP_DIR/venv/bin/pip" install -r "$APP_DIR/requirements.txt"

echo "== 5. Permissions =="
sudo chown -R "$SVC_USER":"$SVC_USER" "$APP_DIR"

echo "== 6. systemd unit =="
sudo cp ./deploy/url-lookup.service /etc/systemd/system/${SVC}.service
sudo systemctl daemon-reload
sudo systemctl enable "$SVC"
sudo systemctl restart "$SVC"

echo "== 7. Status =="
sleep 2
sudo systemctl --no-pager status "$SVC" || true
echo
echo "Health check (direct, pre-nginx):"
curl -fsS http://127.0.0.1:8000/healthz && echo || echo "healthz not responding yet"

echo
echo "Done. '$SVC' on 127.0.0.1:8000, fronted by nginx at /url-lookup/."
