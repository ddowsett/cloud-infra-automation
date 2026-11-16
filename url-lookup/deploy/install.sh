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

echo "== 1. Service user + group =="
# Create the group explicitly: on some images (e.g. the CSAA AL2023 base image)
# `useradd --system` does not create a same-named group, which breaks the
# chown below and the unit's Group= line.
if ! getent group "$SVC_USER" >/dev/null; then
  sudo groupadd --system "$SVC_USER"
fi
if ! id "$SVC_USER" >/dev/null 2>&1; then
  sudo useradd --system --no-create-home --shell /sbin/nologin -g "$SVC_USER" "$SVC_USER"
else
  sudo usermod -g "$SVC_USER" "$SVC_USER"
fi

echo "== 2. App directory =="
sudo mkdir -p "$APP_DIR"

echo "== 3. Copy application files =="
# The repo is normally cloned to /opt/cloud-infra-automation, so running from
# url-lookup/ means source == APP_DIR. cp then fails with "are the same file"
# and set -e aborts the install. Only copy when they differ.
SAME_DIR=false
[ "$(pwd -P)" = "$(readlink -f "$APP_DIR")" ] && SAME_DIR=true
for f in app.py resolver.py audit.py requirements.txt ip_blocks.json excluded_accounts.json; do
  if [ ! -f "./$f" ]; then
    echo "ERROR: missing $f in $(pwd). Run from the url-lookup/ dir." >&2
    exit 1
  fi
  if ! $SAME_DIR; then
    sudo cp "./$f" "$APP_DIR/$f"
  fi
done
if $SAME_DIR; then
  echo "Running from $APP_DIR itself; files already in place."
fi

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
