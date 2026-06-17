#!/bin/bash
#
# BeaconButty demo — one-shot installer for a fresh Raspberry Pi OS Lite.
# Designed to be piped from curl:
#
#   curl -sSL https://raw.githubusercontent.com/mustard-research/beaconbutty-demo/master/bootstrap.sh | sudo bash
#
# After it finishes, browse to http://<pi-ip>:5000/
#
# Override the repo URL with BB_DEMO_REPO=... if you've forked.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "bootstrap.sh: must run as root (use 'sudo bash bootstrap.sh' or pipe via 'sudo bash')" >&2
    exit 1
fi

REPO_URL="${BB_DEMO_REPO:-https://github.com/mustard-research/beaconbutty-demo.git}"
TARGET_DIR="${TARGET_DIR:-/opt/beaconbutty-demo}"
BRANCH="${BB_DEMO_BRANCH:-master}"

echo "==> Installing system dependencies (python3-flask, git)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y --no-install-recommends python3-flask git

echo "==> Cloning ${REPO_URL} (branch ${BRANCH}) into ${TARGET_DIR}"
if [[ -d "${TARGET_DIR}/.git" ]]; then
    git -C "${TARGET_DIR}" fetch --depth=1 origin "${BRANCH}"
    git -C "${TARGET_DIR}" reset --hard "origin/${BRANCH}"
else
    rm -rf "${TARGET_DIR}"
    git clone --depth=1 --branch "${BRANCH}" "${REPO_URL}" "${TARGET_DIR}"
fi

echo "==> Setting ownership"
chown -R www-data:www-data "${TARGET_DIR}"

echo "==> Installing systemd unit"
install -m 644 "${TARGET_DIR}/systemd/beaconbutty-demo.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now beaconbutty-demo

# Give the service a moment to bind the port.
sleep 1
if ! systemctl is-active --quiet beaconbutty-demo; then
    echo "WARNING: beaconbutty-demo.service is not active." >&2
    echo "Run: sudo journalctl -u beaconbutty-demo -n 50 --no-pager" >&2
    exit 2
fi

PI_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
echo ""
echo "================================================================"
echo "  BeaconButty demo installed."
echo "  URL:  http://${PI_IP:-<pi-ip>}:5000/"
echo "  Logs: sudo journalctl -u beaconbutty-demo -f"
echo "  Stop: sudo systemctl stop beaconbutty-demo"
echo "================================================================"
