#!/usr/bin/env python3
"""
Bluetooth Pairing Agent for Pi-ScanMyTesla
Automatically accepts pairing requests (NoInputNoOutput capability)
"""

import dbus
import dbus.service
import dbus.mainloop.glib
from gi.repository import GLib
import subprocess
import sys
import signal
import argparse
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

AGENT_INTERFACE = "org.bluez.Agent1"
AGENT_PATH = "/com/pismt/agent"


class PairingAgent(dbus.service.Object):
    """Bluetooth pairing agent that automatically accepts connections"""

    @dbus.service.method(AGENT_INTERFACE, in_signature="", out_signature="")
    def Release(self):
        logger.info("Agent released")

    @dbus.service.method(AGENT_INTERFACE, in_signature="os", out_signature="")
    def AuthorizeService(self, device, uuid):
        logger.info("AuthorizeService: %s %s - auto-accepting", device, uuid)
        return

    @dbus.service.method(AGENT_INTERFACE, in_signature="o", out_signature="s")
    def RequestPinCode(self, device):
        logger.info("RequestPinCode: %s - returning 0000", device)
        return "0000"

    @dbus.service.method(AGENT_INTERFACE, in_signature="o", out_signature="u")
    def RequestPasskey(self, device):
        logger.info("RequestPasskey: %s - returning 0", device)
        return dbus.UInt32(0)

    @dbus.service.method(AGENT_INTERFACE, in_signature="ouq", out_signature="")
    def DisplayPasskey(self, device, passkey, entered):
        logger.info("DisplayPasskey: %s passkey=%06d entered=%d", device, passkey, entered)

    @dbus.service.method(AGENT_INTERFACE, in_signature="os", out_signature="")
    def DisplayPinCode(self, device, pincode):
        logger.info("DisplayPinCode: %s pincode=%s", device, pincode)

    @dbus.service.method(AGENT_INTERFACE, in_signature="ou", out_signature="")
    def RequestConfirmation(self, device, passkey):
        logger.info("RequestConfirmation: %s passkey=%06d - auto-confirming", device, passkey)
        return

    @dbus.service.method(AGENT_INTERFACE, in_signature="o", out_signature="")
    def RequestAuthorization(self, device):
        logger.info("RequestAuthorization: %s - auto-authorizing", device)
        return

    @dbus.service.method(AGENT_INTERFACE, in_signature="", out_signature="")
    def Cancel(self):
        logger.info("Pairing cancelled")


def enable_discoverable(bt_addr: str) -> None:
    """Enable discoverability via bluetoothctl"""
    try:
        subprocess.run(
            ["bluetoothctl", "select", bt_addr, "discoverable", "on", "pairable", "on"],
            capture_output=True,
            timeout=5
        )
        # Use hciconfig as fallback
        result = subprocess.run(["hciconfig"], capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            if bt_addr.upper() in line.upper():
                # Found the device line, get hci name from previous line
                pass
        subprocess.run(["hciconfig", "hci1", "piscan"], capture_output=True, timeout=5)
        logger.info("Enabled discoverability")
    except Exception as e:
        logger.error("Failed to enable discoverability: %s", e)


def disable_discoverable() -> None:
    """Disable discoverability"""
    try:
        subprocess.run(["hciconfig", "hci1", "pscan"], capture_output=True, timeout=5)
        logger.info("Disabled discoverability (still connectable)")
    except Exception as e:
        logger.error("Failed to disable discoverability: %s", e)


def get_bluetooth_address(device: str) -> str:
    """Get Bluetooth MAC address for device"""
    try:
        result = subprocess.run(
            ['hciconfig', device],
            capture_output=True,
            text=True,
            timeout=5
        )
        for line in result.stdout.split('\n'):
            if 'BD Address:' in line:
                return line.split('BD Address:')[1].split()[0].strip()
    except Exception:
        pass
    return ""


def main():
    parser = argparse.ArgumentParser(description="Bluetooth pairing agent")
    parser.add_argument("--device", default="hci1", help="Bluetooth device (default: hci1)")
    parser.add_argument("--duration", type=int, default=120, help="Pairing window duration in seconds (default: 120)")
    args = parser.parse_args()

    bt_addr = get_bluetooth_address(args.device)
    if not bt_addr:
        logger.error("Could not get Bluetooth address for %s", args.device)
        sys.exit(1)

    logger.info("Starting pairing agent for %s (%s) for %d seconds", args.device, bt_addr, args.duration)

    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()

    agent = PairingAgent(bus, AGENT_PATH)

    manager = dbus.Interface(
        bus.get_object("org.bluez", "/org/bluez"),
        "org.bluez.AgentManager1"
    )

    try:
        manager.RegisterAgent(AGENT_PATH, "NoInputNoOutput")
        manager.RequestDefaultAgent(AGENT_PATH)
        logger.info("Agent registered as default")
    except dbus.exceptions.DBusException as e:
        logger.error("Failed to register agent: %s", e)
        sys.exit(1)

    # Enable discoverability
    enable_discoverable(bt_addr)

    loop = GLib.MainLoop()

    def timeout_handler():
        logger.info("Pairing window expired")
        disable_discoverable()
        loop.quit()
        return False

    def signal_handler(sig, frame):
        logger.info("Signal received, shutting down")
        disable_discoverable()
        loop.quit()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    GLib.timeout_add_seconds(args.duration, timeout_handler)

    logger.info("Pairing window open for %d seconds. Pair from your phone now...", args.duration)

    try:
        loop.run()
    finally:
        try:
            manager.UnregisterAgent(AGENT_PATH)
        except Exception:
            pass


if __name__ == "__main__":
    main()
