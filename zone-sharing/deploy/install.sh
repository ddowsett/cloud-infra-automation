#!/usr/bin/env bash
#
# Install / update the Zone Sharing app (Flask) on Amazon Linux 2023.
# Run from the zone-sharing/ directory of the cloned repo, via SSM or a session.
# Idempotent. Runs on 127.0.0.1:8080 behind nginx at /zone-sharing/.
#
# The front-end page is static/index.html in this folder.
#
set -euo pipefail

APP_DIR=/opt/cloud-infra-automation/zone-sharing
SVC=zone-sharing
SVC_USER=zonesharing

echo "== 1. Service user =="
if ! id "$SVC_USER" >/dev/null 2>&1; then
  sudo useradd --system --no-create-home --shell /sbin/nologin "$SVC_USER"
fi

echo "== 2. App directory =="
sudo mkdir -p "$APP_DIR"

echo "== 3. Copy application files =="
# The repo is normally cloned to /opt/cloud-infra-automation, so running from
# zone-sharing/ means source == APP_DIR. cp then fails with "are the same file"
# and set -e aborts the install. Only copy when they differ.
SAME_DIR=false
[ "$(pwd -P)" = "$(readlink -f "$APP_DIR")" ] && SAME_DIR=true
for f in ShareHostedZoneAutomation.py requirements.txt static/index.html; do
  if [ ! -f "./$f" ]; then
    echo "ERROR: missing $f in $(pwd). Run from the zone-sharing/ dir." >&2
    exit 1
  fi
done
if $SAME_DIR; then
  echo "Running from $APP_DIR itself; files already in place."
else
  sudo cp ./ShareHostedZoneAutomation.py ./requirements.txt "$APP_DIR/"
  sudo mkdir -p "$APP_DIR/static"
  sudo cp ./static/index.html "$APP_DIR/static/index.html"
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
sudo cp ./deploy/zone-sharing.service /etc/systemd/system/${SVC}.service
sudo systemctl daemon-reload
sudo systemctl enable "$SVC"
sudo systemctl restart "$SVC"

echo "== 7. Status =="
sleep 2
sudo systemctl --no-pager status "$SVC" || true
echo
echo "Health check (direct, pre-nginx):"
curl -fsS http://127.0.0.1:8080/ >/dev/null && echo "8080 responding" || echo "8080 not responding yet"

echo
echo "Done. '$SVC' on 127.0.0.1:8080, fronted by nginx at /zone-sharing/."
