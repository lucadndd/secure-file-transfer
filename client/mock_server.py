"""Minimal fake server used to exercise the client by hand.

Framed protocol: 4-byte big-endian length + UTF-8 JSON header + optional
payload, whose length the header announces in "size". Uploads are kept in
memory only, so a name round-trips but nothing survives a restart.
"""
import argparse
import json
import socket
import struct

MAX_HEADER_BYTES = 64 * 1024
MAX_PAYLOAD_BYTES = 100 * 1024 * 1024
CONN_TIMEOUT = 30.0
RECV_CHUNK = 65536

STORE = {"canned.txt": b"canned content from the mock server"}


def read_exactly_n_bytes(conn, n):
    """
    Read exactly n bytes, looping because recv() may return fewer.

    Args:
        conn (socket.socket): connected socket to read from.
        n (int): exact number of bytes to read.

    Returns:
        bytes: exactly n bytes.

    Raises:
        ValueError: if n is negative.
        ConnectionError: if the peer closes first. The message reports how
            many bytes did arrive, which is what you want when a transfer
            is cut short.
        TimeoutError: if the socket's timeout expires.
    """
    if n < 0:
        raise ValueError(f"cannot read a negative number of bytes: {n}")
    data = bytearray()
    while len(data) < n:
        chunk = conn.recv(min(RECV_CHUNK, n - len(data)))
        if not chunk:
            raise ConnectionError(
                f"connection closed after {len(data)} of {n} bytes"
            )
        data.extend(chunk)
    return bytes(data)


def check_size(value, limit, label):
    """
    Validate a peer-announced size before allocating for it.

    Args:
        value: announced size, untrusted and not yet known to be an int.
        limit (int): largest value accepted, in bytes.
        label (str): name of the quantity, used in the error message.

    Returns:
        int: value, unchanged, once known to be safe.

    Raises:
        ValueError: if value is not an int, is a bool (which would
            otherwise pass as one), is negative, or exceeds limit.
    """
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{label} is not an integer: {value!r}")
    if value < 0:
        raise ValueError(f"{label} is negative: {value}")
    if value > limit:
        raise ValueError(f"{label} of {value} bytes exceeds the {limit} byte limit")
    return value


def read_message_header(conn):
    """
    Read and parse one framed header, leaving any payload on the socket.

    Args:
        conn (socket.socket): connected socket to read from.

    Returns:
        dict: the parsed header, e.g. {"op": "UPLOAD", "filename": ..., "size": ...}.

    Raises:
        ValueError: if the length prefix exceeds MAX_HEADER_BYTES, or the
            JSON parses to something other than an object.
        json.JSONDecodeError: if the header bytes are not valid JSON.
        UnicodeDecodeError: if the header bytes are not valid UTF-8.
        ConnectionError: if the peer closes mid-header.
    """
    header_len = struct.unpack(">I", read_exactly_n_bytes(conn, 4))[0]
    check_size(header_len, MAX_HEADER_BYTES, "header length")
    header = json.loads(read_exactly_n_bytes(conn, header_len).decode("utf-8"))
    if not isinstance(header, dict):
        raise ValueError(f"header is not a JSON object: {header!r}")
    return header


def send_message(conn, header, payload=b""):
    """
    Send a framed message in a single sendall(), so it cannot interleave.

    Args:
        conn (socket.socket): connected socket to write to.
        header (dict): serialized as UTF-8 JSON. With a payload, it must
            announce the length in "size".
        payload (bytes): raw file bytes appended after the header.

    Raises:
        OSError: if the peer has already gone away.
    """
    body = json.dumps(header).encode("utf-8")
    conn.sendall(struct.pack(">I", len(body)) + body + payload)


def handle_upload(conn, header):
    """
    Read the announced payload into STORE and acknowledge.

    Args:
        conn (socket.socket): connected socket, positioned just after the
            header, so the next bytes on it are the payload.
        header (dict): parsed UPLOAD header, carrying "filename" and "size".
            An existing entry of the same name is overwritten.

    Raises:
        ValueError: if "size" is unusable, or "filename" is missing, empty,
            or not a string.
        ConnectionError: if the peer closes before the payload is complete.
    """
    size = check_size(header.get("size"), MAX_PAYLOAD_BYTES, "announced size")
    name = header.get("filename")
    if not isinstance(name, str) or not name:
        raise ValueError(f"missing or invalid filename: {name!r}")

    data = read_exactly_n_bytes(conn, size)
    STORE[name] = data
    print(f"Stored {name} ({len(data)} bytes) -> {data[:40]!r}")
    send_message(conn, {"status": "OK"})


def handle_download(conn, header):
    """
    Serve a stored file, or reply ERROR with no payload if it is missing.

    Args:
        conn (socket.socket): connected socket to write to.
        header (dict): parsed DOWNLOAD header, carrying "filename".

    Raises:
        OSError: if the reply cannot be written because the peer has gone.
    """
    name = header.get("filename")
    content = STORE.get(name)
    if content is None:
        send_message(conn, {"status": "ERROR", "error": f"no such file: {name!r}"})
        print(f"Rejected download of {name!r}: not found")
        return

    send_message(conn, {"status": "OK", "size": len(content)}, content)
    print(f"Sent {name} ({len(content)} bytes)")


def handle_connection(conn, addr):
    """
    Answer one request. This is the server's error boundary.

    Every failure a client can provoke becomes an ERROR reply rather than a
    crash. The reply itself is guarded too, since a vanished peer is one of
    the cases being handled.

    Args:
        conn (socket.socket): accepted connection; the caller owns and
            closes it.
        addr (tuple): peer address, used only in log lines.
    """
    print(f"Connection from {addr}")
    conn.settimeout(CONN_TIMEOUT)
    try:
        header = read_message_header(conn)
        print("Received header:", header)

        op = header.get("op")
        if op == "UPLOAD":
            handle_upload(conn, header)
        elif op == "DOWNLOAD":
            handle_download(conn, header)
        else:
            send_message(conn, {"status": "ERROR", "error": f"unknown op: {op!r}"})
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Error handling {addr}: {type(exc).__name__}: {exc}")
        try:
            send_message(conn, {"status": "ERROR", "error": str(exc)})
        except OSError:
            pass


def main():
    """
    Accept and serve connections one at a time until Ctrl-C.

    SO_REUSEADDR is set so a restart need not wait out TIME_WAIT.
    """
    parser = argparse.ArgumentParser(description="mock server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    args = parser.parse_args()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((args.host, args.port))
        server_sock.listen(5)
        print(f"Mock server listening on {args.host}:{args.port} (Ctrl-C to stop)")

        try:
            while True:
                conn, addr = server_sock.accept()
                with conn:
                    handle_connection(conn, addr)
        except KeyboardInterrupt:
            print("\nShutting down")


if __name__ == "__main__":
    main()