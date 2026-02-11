# Pi-ScanMyTesla
CAN to Bluetooth Adapter for [ScanMyTesla](https://sites.google.com/view/scanmytesla/home) on Raspberry Pi

Based on [ESP32-ScanMyTesla](https://github.com/Adminius/ESP32-ScanMyTesla) by Adminius

## Hardware
- Raspberry Pi (tested on Pi 4/5)
- SocketCAN compatible CAN interface (e.g. Waveshare 2-CH CAN HAT, MCP2515) connected to VCAN
- USB Bluetooth adapter recommended (onboard works but USB has better range)
- Does NOT work with iOS. Apple doesn't support Bluetooth Serial.

## Installation

```bash
./setup.sh
sudo systemctl enable pi-scanmytesla
sudo systemctl start pi-scanmytesla
```

## Usage

```bash
# Default (can0, hci0)
python3 pi_scanmytesla.py

# Custom CAN interface and Bluetooth adapter
python3 pi_scanmytesla.py --can-interface can0 --bt-device hci1 --bt-name Pi-SMT
```
