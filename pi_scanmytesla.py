#!/usr/bin/env python3
"""
Pi-ScanMyTesla
Bluetooth SPP to SocketCAN bridge compatible with ScanMyTesla.
"""

import argparse
import logging
import signal
import socket
import subprocess
import threading
import time
from typing import List, Optional

import bluetooth
import can


SPP_UUID = "00001101-0000-1000-8000-00805F9B34FB"
BUFFER_LENGTH = 16
MAX_STD_ID = 2047

logger = logging.getLogger(__name__)


def get_bluetooth_address(device: str) -> Optional[str]:
    """Get Bluetooth MAC address for a given hci device."""
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
    except Exception as e:
        logger.error("Failed to get Bluetooth address for %s: %s", device, e)
    return None


class CanRingBuffer:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._buffer = [None] * BUFFER_LENGTH
        self._write_index = 0
        self._ids = [True] * (MAX_STD_ID + 1)
        self._no_filter = True

    def set_filter(self, can_id: int) -> None:
        if can_id < 0 or can_id > MAX_STD_ID:
            return
        with self._lock:
            if self._no_filter:
                self._ids = [False] * (MAX_STD_ID + 1)
                self._no_filter = False
            self._ids[can_id] = True

    def clear_filters(self) -> None:
        with self._lock:
            self._ids = [True] * (MAX_STD_ID + 1)
            self._no_filter = True

    def add_message(self, can_id: int, data: bytes) -> None:
        if can_id < 0 or can_id > MAX_STD_ID:
            return
        if not (1 <= len(data) <= 8):
            return

        with self._lock:
            if not self._ids[can_id]:
                return

            first_byte = data[0]
            line_index = self._write_index
            for i, entry in enumerate(self._buffer):
                if entry and entry["id"] == can_id and entry["first"] == first_byte:
                    line_index = i
                    break

            self._buffer[line_index] = {
                "id": can_id,
                "data": bytes(data),
                "first": first_byte,
            }

            if line_index == self._write_index:
                self._write_index = (self._write_index + 1) % BUFFER_LENGTH

    def dump_messages(self, debug: bool = False) -> List[str]:
        lines: List[str] = []
        with self._lock:
            for i, entry in enumerate(self._buffer):
                if not entry:
                    continue
                can_id = entry["id"]
                data = entry["data"]
                line = f"{can_id:03x}" + "".join(f"{b:02x}" for b in data)
                if debug and len(lines) < 3:
                    logger.debug("Frame sample: ID=%03x data=%s -> '%s'", can_id, data.hex(), line)
                lines.append(line)
                self._buffer[i] = None
        return lines


class BluetoothSmtServer:
    def __init__(self, name: str, channel: int, can_buffer: CanRingBuffer, device: str = "hci0") -> None:
        self._name = name
        self._channel = channel
        self._can_buffer = can_buffer
        self._device = device
        self._stop_event = threading.Event()
        self._server_socket: Optional[bluetooth.BluetoothSocket] = None

    def start(self) -> None:
        bt_address = get_bluetooth_address(self._device)
        if not bt_address:
            raise RuntimeError(f"Could not get Bluetooth address for {self._device}")
        
        logger.info("Using Bluetooth adapter %s (%s)", self._device, bt_address)
        
        self._server_socket = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
        # Bind to empty string to use default adapter, with specific channel
        self._server_socket.bind(("", self._channel))
        self._server_socket.listen(1)
        self._server_socket.settimeout(1.0)

        # Try to advertise service, but don't fail if it doesn't work
        # SDP should be registered via sdptool add SP
        try:
            bluetooth.advertise_service(
                self._server_socket,
                self._name,
                service_id=SPP_UUID,
                service_classes=[SPP_UUID, bluetooth.SERIAL_PORT_CLASS],
                profiles=[bluetooth.SERIAL_PORT_PROFILE],
            )
            logger.info("Bluetooth SPP service advertised as %s", self._name)
        except Exception as e:
            logger.warning("Could not advertise service (SDP may still work): %s", e)

        logger.info("Bluetooth SPP server started on channel %s", self._channel)
        self._accept_loop()

    def stop(self) -> None:
        self._stop_event.set()
        if self._server_socket:
            try:
                bluetooth.stop_advertising(self._server_socket)
            except Exception:
                pass
            try:
                self._server_socket.close()
            except Exception:
                pass

    def _accept_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                client_socket, client_address = self._server_socket.accept()
            except socket.timeout:
                continue
            except OSError as exc:
                if self._stop_event.is_set():
                    break
                logger.error("Bluetooth accept error: %s", exc)
                continue

            logger.info("Client connected: %s", client_address)
            try:
                self._handle_client(client_socket)
            finally:
                try:
                    client_socket.close()
                except Exception:
                    pass
                logger.info("Client disconnected: %s", client_address)

    def _handle_client(self, client_socket: bluetooth.BluetoothSocket) -> None:
        client_socket.settimeout(1.0)
        cmd_buffer: List[str] = []

        while not self._stop_event.is_set():
            try:
                data = client_socket.recv(256)
            except socket.timeout:
                continue
            except Exception as exc:
                logger.error("Bluetooth receive error: %s", exc)
                break

            if not data:
                break

            for value in data:
                if value == 13 or len(cmd_buffer) >= 127:
                    command = "".join(cmd_buffer)
                    cmd_buffer.clear()
                    response = process_command(command, self._can_buffer)
                    if response:
                        try:
                            client_socket.sendall(response.encode("ascii", errors="ignore"))
                        except Exception as exc:
                            logger.error("Bluetooth send error: %s", exc)
                            return
                elif value in (10, 32):
                    continue
                else:
                    cmd_buffer.append(chr(value).lower())


def parse_filter_id(command: str) -> Optional[int]:
    payload = command[6:].strip()
    if not payload:
        return None
    token = payload.split(",", 1)[0].strip()
    if token.startswith("0x"):
        token = token[2:]
    if not token:
        return None
    try:
        return int(token, 16)
    except ValueError:
        return None


def process_command(command: str, can_buffer: CanRingBuffer) -> str:
    logger.debug("Received command: %r", command)
    
    if not (command.startswith("at") or command.startswith("st")):
        logger.debug("Unknown command, returning newline")
        return "\n"

    if command.startswith("atma") or command.startswith("stm"):
        lines = can_buffer.dump_messages(debug=logger.isEnabledFor(logging.DEBUG))
        logger.debug("Data poll: %d messages in buffer", len(lines))
        if lines:
            response = "\n".join(lines) + "\n>"
            logger.debug("Sending %d bytes", len(response))
            return response
        return ">"

    if command.startswith("stfap "):
        filter_id = parse_filter_id(command)
        if filter_id is not None:
            can_buffer.set_filter(filter_id)
        return "OK>"

    if command.startswith("stfcp"):
        can_buffer.clear_filters()
        return "OK>"

    return "OK>"


def can_reader(stop_event: threading.Event, can_buffer: CanRingBuffer, channel: str) -> None:
    try:
        bus = can.interface.Bus(channel=channel, interface="socketcan")
    except Exception as exc:
        logger.error("Failed to open CAN interface %s: %s", channel, exc)
        return

    try:
        while not stop_event.is_set():
            message = bus.recv(timeout=0.5)
            if message is None:
                continue
            if message.is_error_frame:
                continue
            if message.is_extended_id:
                continue
            can_buffer.add_message(message.arbitration_id, message.data)
    finally:
        try:
            bus.shutdown()
        except Exception:
            pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="ScanMyTesla Bluetooth bridge for SocketCAN")
    parser.add_argument("--can-interface", default="can0", help="SocketCAN interface (default: can0)")
    parser.add_argument("--bt-name", default="Pi-SMT", help="Bluetooth device name")
    parser.add_argument("--bt-device", default="hci0", help="Bluetooth adapter device (default: hci0)")
    parser.add_argument("--bt-channel", type=int, default=1, help="RFCOMM channel (default: 1)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    stop_event = threading.Event()
    can_buffer = CanRingBuffer()

    def handle_signal(_signum, _frame):
        stop_event.set()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    reader_thread = threading.Thread(
        target=can_reader,
        args=(stop_event, can_buffer, args.can_interface),
        daemon=True,
    )
    reader_thread.start()

    server = BluetoothSmtServer(args.bt_name, args.bt_channel, can_buffer, args.bt_device)
    try:
        server.start()
    finally:
        stop_event.set()
        server.stop()
        reader_thread.join(timeout=2.0)


if __name__ == "__main__":
    main()
