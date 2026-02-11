#!/usr/bin/env bash
set -euo pipefail

DURATION_SECONDS="${1:-120}"
BT_DEVICE="${2:-hci1}"

if ! command -v bluetoothctl >/dev/null 2>&1; then
  echo "bluetoothctl not found. Install bluez package." >&2
  exit 1
fi

# Get the MAC address for the device
BT_ADDR=$(hciconfig "$BT_DEVICE" 2>/dev/null | grep -o 'BD Address: [0-9A-F:]*' | cut -d' ' -f3)
if [[ -z "$BT_ADDR" ]]; then
  echo "Could not find Bluetooth address for $BT_DEVICE" >&2
  exit 1
fi

echo "Enabling pairing and discoverability on ${BT_DEVICE} (${BT_ADDR}) for ${DURATION_SECONDS}s..."

bluetoothctl <<EOF
select ${BT_ADDR}
power on
pairable on
discoverable on
agent NoInputNoOutput
default-agent
EOF

echo "Pairing window open. Pair from your phone now..."
sleep "${DURATION_SECONDS}"

echo "Disabling pairing and discoverability on ${BT_DEVICE}."

bluetoothctl <<EOF
select ${BT_ADDR}
pairable off
discoverable off
EOF
