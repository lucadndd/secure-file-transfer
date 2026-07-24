"""File transfer client"""
import argparse
import json
import socket
import struct
import sys
from pathlib import Path

DOWNLOAD_DIR = Path(__file__).resolve().parent / "downloads"
MAX_HEADER_BYTES = 64 * 1024
MAX_PAYLOAD_BYTES = 100 * 1024 * 1024
SOCKET_TIMEOUT = 30.0
RECV_CHUNK = 65536


def build_parser():
    """Build the command-line argument parser for the client."""
    parser = argparse.ArgumentParser(description="client")
    parser.add_argument("op", type=str.upper, choices=["UPLOAD", "DOWNLOAD"], help="Operation to perform (case-insensitive)")
    parser.add_argument("filename", help="File to upload (path) or download (name)")
    parser.add_argument("--host", default="127.0.0.1", help="Server address")
    parser.add_argument("--port", type=int, default=9000, help="Server port")
    return parser


def read_exactly_n_bytes(sock, n):
    """
    Read exactly n bytes from a socket.
    recv() may return fewer bytes than requested, so this loops until the
    full amount has been collected.

    Raises:
        ValueError: if n is negative.
        ConnectionError: if the peer closes before n bytes arrive.
    """
    if n < 0:
        raise ValueError(f"cannot read a negative number of bytes: {n}")
    data = bytearray()
    while len(data) < n:
        chunk = sock.recv(min(RECV_CHUNK, n - len(data)))
        if not chunk:
            raise ConnectionError(
                f"connection closed after {len(data)} of {n} bytes"
            )
        data.extend(chunk)
    return bytes(data)


def check_size(value, limit, label):
    """Validate a size announced by the peer before allocating for it."""
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{label} is not an integer: {value!r}")
    if value < 0:
        raise ValueError(f"{label} is negative: {value}")
    if value > limit:
        raise ValueError(f"{label} of {value} bytes exceeds the {limit} byte limit")
    return value


def read_message_header(sock):
    """
    Read one framed message header: 4-byte big-endian length + UTF-8 JSON.

    Returns:
        dict: the parsed JSON header, e.g. {"status": "OK", "size": ...}.
    """
    header_len = struct.unpack(">I", read_exactly_n_bytes(sock, 4))[0]
    check_size(header_len, MAX_HEADER_BYTES, "header length")
    header = json.loads(read_exactly_n_bytes(sock, header_len).decode("utf-8"))
    if not isinstance(header, dict):
        raise ValueError(f"header is not a JSON object: {header!r}")
    return header


def send_message(sock, header, payload=b""):
    """Send a framed message: 4-byte length + JSON header + optional payload."""
    body = json.dumps(header).encode("utf-8")
    sock.sendall(struct.pack(">I", len(body)) + body + payload)


def require_ok(reply, what):
    """Raise unless the server replied with a success status."""
    if reply.get("status") != "OK":
        raise RuntimeError(
            f"server refused the {what}: {reply.get('error', reply)}"
        )
    return reply


def do_upload(sock, filepath):
    """Send a local file to the server and report the reply."""
    if not filepath.is_file():
        raise FileNotFoundError(f"not a readable file: {filepath}")

    data = filepath.read_bytes()
    check_size(len(data), MAX_PAYLOAD_BYTES, "file size")

    send_message(
        sock,
        {"op": "UPLOAD", "filename": filepath.name, "size": len(data)},
        data,
    )
    require_ok(read_message_header(sock), "upload")
    print(f"Uploaded {filepath.name} ({len(data)} bytes)")


def do_download(sock, filename):
    """Request a file from the server and save it into the downloads folder."""
    safe_name = Path(filename).name
    if not safe_name or safe_name in {".", ".."}:
        raise ValueError(f"unusable file name: {filename!r}")

    send_message(sock, {"op": "DOWNLOAD", "filename": safe_name})

    reply = require_ok(read_message_header(sock), "download")
    size = check_size(reply.get("size"), MAX_PAYLOAD_BYTES, "announced size")
    data = read_exactly_n_bytes(sock, size)

    DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)
    destination = DOWNLOAD_DIR / safe_name
    destination.write_bytes(data)
    print(f"Downloaded {safe_name} ({len(data)} bytes) -> {destination}")


def main():
    """Connect to the server and perform one upload or download."""
    args = build_parser().parse_args()

    try:
        with socket.create_connection(
            (args.host, args.port), timeout=SOCKET_TIMEOUT
        ) as sock:
            if args.op == "UPLOAD":
                do_upload(sock, Path(args.filename))
            else:
                do_download(sock, args.filename)
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())