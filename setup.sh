#!/usr/bin/env bash
set -euo pipefail

sudo apt-get update
sudo apt-get install -y \
  python3-pip \
  python3-venv \
  python3-dev \
  bluez \
  bluez-tools \
  bluetooth \
  python3-bluez \
  libbluetooth-dev \
  libglib2.0-dev \
  can-utils

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [[ ! -d venv ]]; then
  python3 -m venv venv
fi

./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r requirements.txt

cat <<'EOF'

Note: BlueZ may require legacy SDP support for RFCOMM advertising.
If needed, edit /lib/systemd/system/bluetooth.service and add -C to ExecStart:
  ExecStart=/usr/lib/bluetooth/bluetoothd -C
Then run:
  sudo systemctl daemon-reload
  sudo systemctl restart bluetooth

Bluetooth module is provided by the python3-bluez package on Raspberry Pi OS.

EOF
