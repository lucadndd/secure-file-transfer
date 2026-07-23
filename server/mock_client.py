"""Minimal fake client to test the server by hand."""
import json
import socket
import struct


def send_framed(sock, header, payload=b""):
    """Send a message: 4-byte length + JSON header + optional payload."""
    body = json.dumps(header).encode("utf-8")
    sock.sendall(struct.pack(">I", len(body)) + body + payload)


def main():
    host, port = "127.0.0.1", 9000
    filename = "test.txt"
    content = b"hello from the mock client"

    with socket.create_connection((host, port)) as sock:
        header = {"op": "UPLOAD", "filename": filename, "size": len(content)}
        send_framed(sock, header, content)
        print(f"Sent: {header}")

        raw = sock.recv(4096)
        if raw:
            reply_len = struct.unpack(">I", raw[:4])[0]
            print("Reply:", json.loads(raw[4:4 + reply_len].decode("utf-8")))


if __name__ == "__main__":
    main()