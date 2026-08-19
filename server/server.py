import argparse
import hashlib
import hmac
import json
import socket
import ssl
import struct
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CERTS_DIR = PROJECT_ROOT / "certs"
DEFAULT_CERT_PATH = CERTS_DIR / "server-cert.pem"
DEFAULT_KEY_PATH = CERTS_DIR / "server-key.pem"
DEFAULT_CA_PATH = CERTS_DIR / "ca-cert.pem"

STORAGE_DIR = Path(__file__).parent / "storage"
MAX_HEADER_BYTES = 64 * 1024
MAX_PAYLOAD_BYTES = 100 * 1024 * 1024
SOCKET_TIMEOUT = 30.0
DIGEST_HEX_LENGTH = 64
DIGEST_SUFFIX = ".sha256"


def build_parser():
    """
    Build the command-line argument parser for the server.

    The certificate paths are resolved from the location of this file, so
    that the server can be started from any working directory.

    Returns:
        argparse.ArgumentParser: parser accepting --host, --port, --certfile, --keyfile and --cafile.
    """
    parser = argparse.ArgumentParser(description="server")
    parser.add_argument("--host", default="127.0.0.1", help="Address to bind")
    parser.add_argument("--port", type=int, default=9000, help="Port to listen on")
    parser.add_argument("--certfile", type=Path, default=DEFAULT_CERT_PATH,
        help="Certificate presented to clients")
    parser.add_argument("--keyfile", type=Path, default=DEFAULT_KEY_PATH,
        help="Private key matching the certificate")
    parser.add_argument("--cafile", type=Path, default=DEFAULT_CA_PATH,
        help="Authority that client certificates must chain to")
    return parser


def build_tls_context(certfile, keyfile, cafile):
    """
    Build the TLS context the server presents to clients.

    Every client must present a certificate that chains to the given
    authority, so an unauthenticated peer is turned away during the
    handshake and never reaches the application protocol. The lowest
    acceptable protocol version is stated here rather than left to the
    library default, so that the policy travels with the program.

    Args:
        certfile (Path): certificate to present.
        keyfile (Path): private key matching the certificate.
        cafile (Path): authority that client certificates must chain to.

    Returns:
        ssl.SSLContext: context ready to wrap accepted connections.

    Raises:
        OSError: if any of the files cannot be read. ssl.SSLError: if the key does not match the certificate.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    context.load_verify_locations(cafile=cafile)
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def peer_common_name(tls_conn):
    """
    Read the common name from the certificate the peer presented.

    Only meaningful after a successful handshake: with CERT_REQUIRED a
    client without a valid certificate never gets this far.

    Args:
        tls_conn (ssl.SSLSocket): connection whose handshake has completed.

    Returns:
        str | None: the subject common name, or None if the certificate
        carries none.
    """
    subject = dict(entry[0] for entry in tls_conn.getpeercert()["subject"])
    return subject.get("commonName")


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

    The announced length is checked before reading, so that a peer cannot
    make the server allocate an arbitrary amount of memory.

    Args:
        conn (socket.socket): connected socket to read from.

    Returns:
        dict: the parsed JSON header, such as
        {"op": "UPLOAD", "filename": ..., "size": ...}.

    Raises:
        ValueError: if the announced length exceeds MAX_HEADER_BYTES, or if
        the header bytes are not valid UTF-8, or not valid JSON, or parse to
        something other than an object.
        ConnectionError: if the peer closes before the header is complete.
    """
    raw_len = read_exactly_n_bytes(conn, 4)
    header_len = struct.unpack(">I", raw_len)[0]
    if header_len > MAX_HEADER_BYTES:
        raise ValueError(
            f"announced header of {header_len} bytes exceeds the "
            f"{MAX_HEADER_BYTES} byte limit"
        )
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

    A single dot is rejected on its own and not as a substring: it names
    the directory it is joined to rather than a file inside it, while any
    ordinary name carrying an extension must stay acceptable.

    Args:
        name: file name taken from a message header; any JSON value, since
        the peer chooses what to send.

    Returns:
        bool: False if the name is not a non-empty string, or if it could
        escape the storage directory or name the directory itself.
    """
    return (
        isinstance(name, str)
        and bool(name)
        and name != "."
        and "/" not in name
        and "\\" not in name
        and ".." not in name
    )


def sha256_hex(data):
    """
    Return the SHA-256 of some bytes as lowercase hexadecimal.

    Args:
        data (bytes): content to digest.

    Returns:
        str: 64 hexadecimal characters.
    """
    return hashlib.sha256(data).hexdigest()


def is_valid_digest(digest):
    """
    Check whether a digest announced by a peer is well-formed.

    Args:
        digest: value taken from a message header; any JSON value, since
        the peer chooses what to send.

    Returns:
        bool: True for exactly 64 lowercase hexadecimal characters.
    """
    return (
        isinstance(digest, str)
        and len(digest) == DIGEST_HEX_LENGTH
        and all(c in "0123456789abcdef" for c in digest)
    )


def digest_path(storage_dir, filename):
    """
    Return the file the digest of a stored file is written to.

    Args:
        storage_dir (Path): directory holding the file.
        filename (str): name of the file the digest belongs to.

    Returns:
        Path: destination file.
    """
    return storage_dir / f"{filename}{DIGEST_SUFFIX}"


def handle_upload(conn, header, storage_dir):
    """
    Receive the file announced in the header and save it to storage.

    The announced size is checked before reading, so that a peer cannot make
    the server allocate an arbitrary amount of memory. The storage space is
    created on the first upload, so a client that only downloads never gets
    one. The digest is checked before the file is opened, so a payload that
    does not match leaves nothing on disk. The digest file is written first,
    so that a data file cannot be left without one.

    Args:
        conn (socket.socket): connected socket to read the payload from.
        header (dict): parsed UPLOAD header with "filename", "size" and
        "sha256" keys.
        storage_dir (Path): directory the file is written to.
    """
    filename = header.get("filename")
    size = header.get("size")
    digest = header.get("sha256")

    if not isinstance(size, int) or size < 0 or size > MAX_PAYLOAD_BYTES:
        send_message(conn, {"status": "ERROR", "reason": "bad_request"})
        print(f"Rejected upload with missing or invalid size: {size!r}")
        return

    if not is_safe_name(filename):
        send_message(conn, {"status": "ERROR", "reason": "invalid_name"})
        print(f"Rejected unsafe file name: {filename!r}")
        return

    if not is_valid_digest(digest):
        send_message(conn, {"status": "ERROR", "reason": "bad_request"})
        print(f"Rejected upload with missing or invalid digest: {digest!r}")
        return

    data = read_exactly_n_bytes(conn, size)

    if not hmac.compare_digest(sha256_hex(data), digest):
        send_message(conn, {"status": "ERROR", "reason": "integrity_failed"})
        print(f"Refused {filename}: payload does not match the announced digest")
        return

    storage_dir.mkdir(exist_ok=True)
    recorded = digest_path(storage_dir, filename)

    try:
        with open(recorded, "x") as f:
            f.write(digest)
    except FileExistsError:
        send_message(conn, {"status": "ERROR", "reason": "already_exists"})
        print(f"Refused to overwrite existing file: {filename}")
        return

    try:
        with open(storage_dir / filename, "xb") as f:
            f.write(data)
    except FileExistsError:
        recorded.unlink()
        send_message(conn, {"status": "ERROR", "reason": "already_exists"})
        print(f"Refused to overwrite existing file: {filename}")
        return

    send_message(conn, {"status": "OK"})
    print(f"Saved {filename} ({size} bytes)")


def handle_download(conn, header, storage_dir):
    """
    Send the file requested in the header back to the client.

    A file with no recorded digest is reported as absent, so that an
    incomplete pair is not distinguishable from a file that never existed.

    Args:
        conn (socket.socket): connected socket to write to.
        header (dict): parsed DOWNLOAD header with a "filename" key.
        storage_dir (Path): directory the file is read from.
    """
    filename = header.get("filename")

    if not is_safe_name(filename):
        send_message(conn, {"status": "ERROR", "reason": "invalid_name"})
        print(f"Rejected unsafe file name: {filename!r}")
        return

    path = storage_dir / filename
    if not path.is_file():
        send_message(conn, {"status": "ERROR", "reason": "not_found"})
        print(f"Requested file not found: {filename}")
        return

    recorded = digest_path(storage_dir, filename)
    if not recorded.is_file():
        send_message(conn, {"status": "ERROR", "reason": "not_found"})
        print(f"Refused {filename}: stored digest missing")
        return

    data = path.read_bytes()
    digest = recorded.read_text().strip()

    if not hmac.compare_digest(sha256_hex(data), digest):
        send_message(conn, {"status": "ERROR", "reason": "integrity_failed"})
        print(f"Refused {filename}: stored file diverges from recorded digest")
        return

    send_message(conn,{"status": "OK", "size": len(data), "sha256": digest},data,)
    print(f"Sent {filename} ({len(data)} bytes)")


def handle_request(conn, storage_dir):
    """
    Read one request and dispatch it to the matching handler.

    Args:
        conn (socket.socket): connected socket to serve.
        storage_dir (Path): directory the request is resolved against.
    """
    try:
        header = read_message_header(conn)
    except ValueError as e:
        send_message(conn, {"status": "ERROR", "reason": "bad_request"})
        print(f"Rejected malformed request: {e}")
        return

    op = header.get("op")
    if op == "UPLOAD":
        handle_upload(conn, header, storage_dir)
    elif op == "DOWNLOAD":
        handle_download(conn, header, storage_dir)
    else:
        send_message(conn, {"status": "ERROR", "reason": "bad_request"})
        print(f"Rejected unknown operation: {op!r}")


def main():
    """
    Bind the listening socket and serve one TLS connection after another.
    Each connection carries a single request and is then closed. A client
    that fails authentication costs that connection only, and connections
    time out, so that a silent peer cannot hold the loop indefinitely.
    """
    args = build_parser().parse_args()

    STORAGE_DIR.mkdir(exist_ok=True)
    context = build_tls_context(args.certfile, args.keyfile, args.cafile)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((args.host, args.port))
        server_sock.listen()
        print(f"Server listening on {args.host}:{args.port} over  mTLS")

        try:
            while True:
                conn, addr = server_sock.accept()
                with conn:
                    conn.settimeout(SOCKET_TIMEOUT)
                    print(f"Connection from {addr}")
                    try:
                        with context.wrap_socket(conn, server_side=True) as tls_conn:
                            identity = peer_common_name(tls_conn)
                            if not is_safe_name(identity):
                                print(f"Rejected unusable client identity: {identity!r}")
                                continue
                            print(f"Authenticated client: {identity}")
                            handle_request(tls_conn, STORAGE_DIR / identity)
                    except ssl.SSLError as e:
                        print(f"TLS handshake failed: {e}")
                    except (ConnectionError, OSError) as e:
                        print(f"Connection lost: {e}")
        except KeyboardInterrupt:
            print("\nShutting down")


if __name__ == "__main__":
    main()