#!/bin/bash
#
# BeaconButty demo — local installer.
#
# Run this from inside an existing checkout:
#
#   git clone https://github.com/mustard-research/beaconbutty-demo
#   cd beaconbutty-demo
#   sudo bash install.sh
#
# Use bootstrap.sh instead if you want a single-shot "fetch + install"
# from a fresh Pi.

set -euo pipefail

INSTALL_DIR="/opt/beaconbutty-demo"
SERVICE_NAME="beaconbutty-demo"
REPO_DIR="$(cd "$(dirname "$0")" && pwd)"

if [[ $EUID -ne 0 ]]; then
    echo "install.sh: must run as root (use 'sudo bash install.sh')" >&2
    exit 1
fi

echo "==> Installing python3-flask"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y --no-install-recommends python3-flask

echo "==> Copying app to ${INSTALL_DIR}"
mkdir -p "${INSTALL_DIR}"
cp -r "${REPO_DIR}"/{app.py,demo_data.py,templates,static} "${INSTALL_DIR}/"
chown -R www-data:www-data "${INSTALL_DIR}"

echo "==> Installing systemd unit"
install -m 644 "${REPO_DIR}/systemd/${SERVICE_NAME}.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now "${SERVICE_NAME}"

sleep 1
if ! systemctl is-active --quiet "${SERVICE_NAME}"; then
    echo "WARNING: ${SERVICE_NAME}.service is not active." >&2
    echo "Run: sudo journalctl -u ${SERVICE_NAME} -n 50 --no-pager" >&2
    exit 2
fi

PI_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
echo ""
echo "==> Done. BeaconButty demo is running on port 5000."
echo "    Browse to: http://${PI_IP:-<pi-ip>}:5000/"
