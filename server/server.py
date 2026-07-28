import argparse
import json
import socket
import struct
from pathlib import Path

STORAGE_DIR = Path(__file__).parent / "storage"


def build_parser():
    """
    Build the command-line argument parser for the server.

    Returns:
        argparse.ArgumentParser: parser accepting --host and --port.
    """
    parser = argparse.ArgumentParser(description="server")
    parser.add_argument("--host", default="127.0.0.1", help="Address to bind")
    parser.add_argument("--port", type=int, default=9000, help="Port to listen on")
    return parser


def read_exactly_n_bytes(conn, n):
    """
    Read exactly n bytes from a socket.

    conn.recv() may return fewer bytes than requested, so this loops until
    the full amount has been collected.

    Args:
        conn (socket.socket): connected socket to read from.
        n (int): exact number of bytes to read.

    Returns:
        bytes: exactly n bytes.

    Raises:
        ConnectionError: if the peer closes before n bytes arrive.
    """
    data = bytearray()
    while len(data) < n:
        chunk = conn.recv(min(4096, n - len(data)))
        if not chunk:
            raise ConnectionError("connection closed before all data was received")
        data.extend(chunk)
    return bytes(data)


def read_message_header(conn):
    """
    Read one framed message header from a socket.

    Args:
        conn (socket.socket): connected socket to read from.

    Returns:
        dict: the parsed JSON header, such as
        {"op": "UPLOAD", "filename": ..., "size": ...}.

    Raises:
        ValueError: if the header bytes are not valid UTF-8, or not valid
        JSON, or parse to something other than an object.
        ConnectionError: if the peer closes before the header is complete.
    """
    raw_len = read_exactly_n_bytes(conn, 4)
    header_len = struct.unpack(">I", raw_len)[0]
    header_bytes = read_exactly_n_bytes(conn, header_len)
    header = json.loads(header_bytes.decode("utf-8"))
    if not isinstance(header, dict):
        raise ValueError(f"header is not a JSON object: {header!r}")
    return header


def send_message(conn, header, payload=b""):
    """
    Send a framed message: 4-byte length + JSON header + optional payload.

    Args:
        conn (socket.socket): connected socket to write to.
        header (dict): message header, serialized as UTF-8 JSON.
        payload (bytes): raw file bytes appended after the header.
    """
    body = json.dumps(header).encode("utf-8")
    conn.sendall(struct.pack(">I", len(body)) + body + payload)


def is_safe_name(name):
    """
    Check whether a file name is safe.

    Args:
        name (str): file name taken from a message header.

    Returns:
        bool: False if the name could escape the storage directory.
    """
    return bool(name) and "/" not in name and "\\" not in name and ".." not in name


def handle_upload(conn, header):
    """
    Receive the file announced in the header and save it to storage.

    Args:
        conn (socket.socket): connected socket to read the payload from.
        header (dict): parsed UPLOAD header with "filename" and "size" keys.
    """
    filename = header.get("filename")
    size = header.get("size")

    if not isinstance(size, int) or size < 0:
        send_message(conn, {"status": "ERROR", "reason": "bad_request"})
        print("Rejected upload with missing or invalid size")
        return

    if not is_safe_name(filename):
        send_message(conn, {"status": "ERROR", "reason": "invalid_name"})
        print(f"Rejected unsafe file name: {filename!r}")
        return

    data = read_exactly_n_bytes(conn, size)
    with open(STORAGE_DIR / filename, "wb") as f:
        f.write(data)

    send_message(conn, {"status": "OK"})
    print(f"Saved {filename} ({size} bytes)")


def handle_download(conn, header):
    """
    Send the file requested in the header back to the client.

    Args:
        conn (socket.socket): connected socket to write to.
        header (dict): parsed DOWNLOAD header with a "filename" key.
    """
    filename = header.get("filename")

    if not is_safe_name(filename):
        send_message(conn, {"status": "ERROR", "reason": "invalid_name"})
        print(f"Rejected unsafe file name: {filename!r}")
        return

    path = STORAGE_DIR / filename
    if not path.is_file():
        send_message(conn, {"status": "ERROR", "reason": "not_found"})
        print(f"Requested file not found: {filename}")
        return

    data = path.read_bytes()

    send_message(conn, {"status": "OK", "size": len(data)}, data)
    print(f"Sent {filename} ({len(data)} bytes)")


def handle_request(conn):
    """
    Read one request and dispatch it to the matching handler.

    Args:
        conn (socket.socket): connected socket to serve.
    """
    try:
        header = read_message_header(conn)
    except ValueError as e:
        send_message(conn, {"status": "ERROR", "reason": "bad_request"})
        print(f"Rejected malformed request: {e}")
        return

    op = header.get("op")
    if op == "UPLOAD":
        handle_upload(conn, header)
    elif op == "DOWNLOAD":
        handle_download(conn, header)
    else:
        send_message(conn, {"status": "ERROR", "reason": "bad_request"})
        print(f"Rejected unknown operation: {op!r}")


def main():
    """
    Bind the listening socket and serve one connection after another.
    Each connection carries a single request and is then closed.
    """
    args = build_parser().parse_args()

    STORAGE_DIR.mkdir(exist_ok=True)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((args.host, args.port))
        server_sock.listen()
        print(f"Server listening on {args.host}:{args.port}")

        try:
            while True:
                conn, addr = server_sock.accept()
                with conn:
                    print(f"Connection from {addr}")
                    try:
                        handle_request(conn)
                    except (ConnectionError, OSError) as e:
                        print(f"Connection lost: {e}")
        except KeyboardInterrupt:
            print("\nShutting down")


if __name__ == "__main__":
    main()