import argparse
import json
import socket
import struct
from pathlib import Path

STORAGE_DIR = Path(__file__).parent / "storage"


def build_parser():
    parser = argparse.ArgumentParser(description="server")
    parser.add_argument("--host", default="127.0.0.1", help="Address to bind")
    parser.add_argument("--port", type=int, default=9000, help="Port to listen on")
    return parser


def read_exactly_n_bytes(conn, n):
    data = bytearray()
    while len(data) < n:
        chunk = conn.recv(min(4096, n - len(data)))
        if not chunk:
            raise ConnectionError("connection closed before all data was received")
        data.extend(chunk)
    return bytes(data)


def read_message_header(conn):
    raw_len = read_exactly_n_bytes(conn, 4)
    header_len = struct.unpack(">I", raw_len)[0]
    header_bytes = read_exactly_n_bytes(conn, header_len)
    return json.loads(header_bytes.decode("utf-8"))


def send_reply(conn, status):
    body = json.dumps({"status": status}).encode("utf-8")
    conn.sendall(struct.pack(">I", len(body)) + body)


def handle_upload(conn, header):
    filename = header["filename"]
    size = header["size"]

    data = read_exactly_n_bytes(conn, size)
    with open(STORAGE_DIR / filename, "wb") as f:
        f.write(data)

    send_reply(conn, "OK")
    print(f"Saved {filename} ({size} bytes)")


def main():
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
            handle_upload(conn, header)


if __name__ == "__main__":
    main()