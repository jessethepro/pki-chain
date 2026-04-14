#!/usr/bin/env python3
"""Minimal client for PKI Chain Unix socket protocol.

Protocol framing (little-endian):
- u32: version
- u32: payload length in bytes
- bytes: UTF-8 JSON payload

The request JSON must include:
- request_type
- response_socket (path the server will connect back to)
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import struct
import tempfile
from pathlib import Path
from typing import Dict

PROTOCOL_VERSION = 1
MAX_PAYLOAD_SIZE = 10 * 1024 * 1024


def read_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Socket closed while reading data")
        data.extend(chunk)
    return bytes(data)


def recv_framed_json(sock: socket.socket) -> Dict[str, object]:
    header = read_exact(sock, 8)
    version, payload_size = struct.unpack("<II", header)

    if version != PROTOCOL_VERSION:
        raise ValueError(
            f"Unexpected protocol version: {version} (expected {PROTOCOL_VERSION})"
        )
    if payload_size > MAX_PAYLOAD_SIZE:
        raise ValueError(f"Payload too large: {payload_size} bytes")

    payload = read_exact(sock, payload_size)
    return json.loads(payload.decode("utf-8"))


def send_framed_json(sock: socket.socket, payload_obj: Dict[str, object]) -> None:
    payload = json.dumps(payload_obj, separators=(",", ":")).encode("utf-8")
    header = struct.pack("<II", PROTOCOL_VERSION, len(payload))
    sock.sendall(header + payload)


def parse_key_values(items: list[str]) -> Dict[str, str]:
    parsed: Dict[str, str] = {}
    for item in items:
        if "=" not in item:
            raise ValueError(f"Invalid --field value '{item}', expected key=value")
        key, value = item.split("=", 1)
        if not key:
            raise ValueError("Field key cannot be empty")
        parsed[key] = value
    return parsed


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Send a request to the PKI Chain Unix socket server"
    )
    parser.add_argument(
        "--server-socket",
        required=True,
        help="Path to server Unix socket (e.g. /tmp/pki-chain.sock)",
    )
    parser.add_argument(
        "--request-type",
        default="GetState",
        help="Value for request_type in request JSON (default: GetState)",
    )
    parser.add_argument(
        "--field",
        action="append",
        default=[],
        help="Additional request field as key=value (repeatable)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Socket timeout in seconds (default: 5.0)",
    )
    parser.add_argument(
        "--raw",
        action="store_true",
        help="Print compact JSON instead of pretty output",
    )

    args = parser.parse_args()

    request_data: Dict[str, object] = {
        "request_type": args.request_type,
    }
    request_data.update(parse_key_values(args.field))

    with tempfile.TemporaryDirectory(prefix="pki-chain-client-") as tmp_dir:
        response_socket_path = str(Path(tmp_dir) / "response.sock")
        request_data["response_socket"] = response_socket_path

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as response_listener:
            response_listener.settimeout(args.timeout)
            response_listener.bind(response_socket_path)
            response_listener.listen(1)

            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as request_socket:
                request_socket.settimeout(args.timeout)
                request_socket.connect(args.server_socket)
                send_framed_json(request_socket, request_data)

            conn, _ = response_listener.accept()
            with conn:
                conn.settimeout(args.timeout)
                response = recv_framed_json(conn)

    if args.raw:
        print(json.dumps(response, separators=(",", ":")))
    else:
        print(json.dumps(response, indent=2, sort_keys=True))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
