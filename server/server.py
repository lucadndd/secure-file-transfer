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

    The wire format is a 4-byte big-endian length prefix followed by that many
    bytes of UTF-8 JSON.

    Args:
        conn (socket.socket): connected socket to read from.

    Returns:
        dict: the parsed JSON header, e.g. {"op": "UPLOAD", "filename": ..., "size": ...}.
    """
    raw_len = read_exactly_n_bytes(conn, 4)
    header_len = struct.unpack(">I", raw_len)[0]
    header_bytes = read_exactly_n_bytes(conn, header_len)
    return json.loads(header_bytes.decode("utf-8"))


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


def handle_upload(conn, header):
    """
    Receive the file announced in the header and save it to storage.

    Reads exactly the number of bytes declared in the header, writes them to
    the storage directory under the given file name, and replies to the client.

    Args:
        conn (socket.socket): connected socket to read the payload from.
        header (dict): parsed UPLOAD header with "filename" and "size" keys.
    """
    filename = header["filename"]
    size = header["size"]

    data = read_exactly_n_bytes(conn, size)
    with open(STORAGE_DIR / filename, "wb") as f:
        f.write(data)

    send_message(conn, {"status": "OK"})
    print(f"Saved {filename} ({size} bytes)")


def handle_download(conn, header):
    """
    Send the file requested in the header back to the client.

    Reads the file from the storage directory and replies with its size,
    followed by the raw file bytes.

    Args:
        conn (socket.socket): connected socket to write to.
        header (dict): parsed DOWNLOAD header with a "filename" key.
    """
    filename = header["filename"]
    data = (STORAGE_DIR / filename).read_bytes()

    send_message(conn, {"status": "OK", "size": len(data)}, data)
    print(f"Sent {filename} ({len(data)} bytes)")


def main():
    """
    Start the server, accept a single connection, and handle one request.

    Binds a TCP socket to the configured host and port, waits for one client,
    reads the framed header and dispatches on its "op" field.
    """
    args = build_parser().parse_args()

    STORAGE_DIR.mkdir(exist_ok=True)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((args.host, args.port))
        server_sock.listen(1)
        print(f"Server listening on {args.host}:{args.port}")

        conn, addr = server_sock.accept()
        with conn:
            print(f"Connection from {addr}")
            header = read_message_header(conn)

            if header["op"] == "UPLOAD":
                handle_upload(conn, header)
            elif header["op"] == "DOWNLOAD":
                handle_download(conn, header)


if __name__ == "__main__":
    main()