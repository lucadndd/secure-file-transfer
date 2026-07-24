"""Minimal fake client to test the server by hand."""
import argparse
import json
import socket
import struct


def send_framed(sock, header, payload=b""):
    """
    Send a framed message: 4-byte length + JSON header + optional payload.
    """
    body = json.dumps(header).encode("utf-8")
    sock.sendall(struct.pack(">I", len(body)) + body + payload)


def read_framed_header(sock):
    """
    Read a framed reply header and return it as a dict.
    """
    raw_len = sock.recv(4)
    header_len = struct.unpack(">I", raw_len)[0]
    return json.loads(sock.recv(header_len).decode("utf-8"))


def do_upload(sock, filename):
    """
    Upload a small in-memory file and print the server reply.
    """
    content = b"hello from the mock client"
    send_framed(sock, {"op": "UPLOAD", "filename": filename, "size": len(content)}, content)
    print("Reply:", read_framed_header(sock))


def do_download(sock, filename):
    """
    Request a file and print the reply plus the received content.
    """
    send_framed(sock, {"op": "DOWNLOAD", "filename": filename})
    header = read_framed_header(sock)
    print("Reply:", header)

    data = b""
    while len(data) < header["size"]:
        data += sock.recv(header["size"] - len(data))
    print("Content:", data)


def main():
    """
    Send one UPLOAD or DOWNLOAD message to the server.
    """
    parser = argparse.ArgumentParser(description="mock client")
    parser.add_argument("op", choices=["upload", "download"])
    parser.add_argument("--filename", default="test.txt")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    args = parser.parse_args()

    with socket.create_connection((args.host, args.port)) as sock:
        if args.op == "upload":
            do_upload(sock, args.filename)
        else:
            do_download(sock, args.filename)


if __name__ == "__main__":
    main()