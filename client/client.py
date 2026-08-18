"""File transfer client"""
import argparse
import json
import socket
import ssl
import struct
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent
DOWNLOAD_DIR = BASE_DIR / "downloads"
CERTS_DIR = PROJECT_ROOT / "certs"
CA_CERT_PATH = CERTS_DIR / "ca-cert.pem"
DEFAULT_IDENTITY = "alice"
MAX_HEADER_BYTES = 64 * 1024
MAX_PAYLOAD_BYTES = 100 * 1024 * 1024
SOCKET_TIMEOUT = 30.0
RECV_CHUNK = 65536

REASON_MESSAGES = {
    "not_found": "the server has no file with that name",
    "already_exists": "the server already has a file with that name",
    "invalid_name": "that file name is not allowed (no '/', '\\' or '..')",
    "bad_request": "the server could not understand the request",
}


def build_parser():
    """Build the command-line argument parser for the client."""
    parser = argparse.ArgumentParser(description="client")
    parser.add_argument("op", type=str.upper, choices=["UPLOAD", "DOWNLOAD"], help="Operation to perform (case-insensitive)")
    parser.add_argument("filename", help="File to upload (path) or download (name)")
    parser.add_argument("--host", default="127.0.0.1", help="Server address")
    parser.add_argument("--port", type=int, default=9000, help="Server port")
    parser.add_argument("--identity", default=DEFAULT_IDENTITY, help="Name of the certificate pair in certs/ to present")
    parser.add_argument("--certfile", type=Path, default=None, help="Client certificate to present, in PEM form; overrides --identity")
    parser.add_argument("--keyfile", type=Path, default=None, help="Private key matching --certfile, in PEM form; overrides --identity")
    return parser


def build_tls_context(certfile, keyfile):
    """
    Build the TLS context used for the outgoing connection.

    Args:
        certfile (Path): client certificate to present, in PEM form.
        keyfile (Path): private key matching certfile, in PEM form.

    Returns:
        ssl.SSLContext: context for a mutually authenticated connection.

    Raises:
        FileNotFoundError: if any of the certificate files is missing.
        RuntimeError: if the certificate and the key do not belong together.
    """
    for label, path in (
        ("CA certificate", CA_CERT_PATH),
        ("client certificate", certfile),
        ("client private key", keyfile),
    ):
        if not path.is_file():
            raise FileNotFoundError(
                f"{label} not found at {path}: run certs/generate_certs.py first"
            )

    context = ssl.create_default_context(cafile=str(CA_CERT_PATH))
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    try:
        context.load_cert_chain(certfile, keyfile)
    except ssl.SSLError as exc:
        raise RuntimeError(
            f"Could not load the client identity: {certfile} and {keyfile} "
            f"do not belong together ({exc.reason})."
        ) from exc

    return context


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
                f"connection closed after {len(data)} of {n} bytes")
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


def is_valid_name(name):
    """
    Report whether a file name is safe to send or save under.

    Args:
        name (str): candidate file name.

    Returns:
        bool: False if the name is empty or could escape a directory.
    """
    return bool(name) and not any(bad in name for bad in ("/", "\\", ".."))


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


def require_ok(reply):
    """Raise unless the server replied with a success status."""
    if reply.get("status") == "OK":
        return reply
    reason = reply.get("reason")
    detail = REASON_MESSAGES.get(reason, f"unrecognised reason {reason!r}")
    raise RuntimeError(f"Server rejected the request: {detail}.")


def validate_request(args):
    """
    Reject impossible requests before opening a connection.

    Args:
        args (argparse.Namespace): parsed command-line arguments.

    Raises:
        FileNotFoundError: if an upload source is not a readable file.
        ValueError: if the file name is not acceptable, or if an upload
        exceeds the payload limit.
    """
    if args.op == "UPLOAD":
        path = Path(args.filename)
        if not path.is_file():
            raise FileNotFoundError(f"not a readable file: {path}")
        if not is_valid_name(path.name):
            raise ValueError(f"cannot upload under the name {path.name!r}")
        check_size(path.stat().st_size, MAX_PAYLOAD_BYTES, "file size")
    elif not is_valid_name(args.filename):
        raise ValueError(
            f"invalid file name {args.filename!r}: it may not contain '/', '\\' or '..'"
        )


def do_upload(sock, filepath):
    """Send a local file to the server and report the reply."""
    if not filepath.is_file():
        raise FileNotFoundError(f"not a readable file: {filepath}")
    if not is_valid_name(filepath.name):
        raise ValueError(f"cannot upload under the name {filepath.name!r}")

    check_size(filepath.stat().st_size, MAX_PAYLOAD_BYTES, "file size")
    data = filepath.read_bytes()
    check_size(len(data), MAX_PAYLOAD_BYTES, "file size after reading")

    send_message(
        sock,
        {"op": "UPLOAD", "filename": filepath.name, "size": len(data)},
        data,
    )
    require_ok(read_message_header(sock))
    print(f"Uploaded {filepath.name} ({len(data)} bytes)")


def do_download(sock, filename):
    """Request a file from the server and save it into the 'downloads' folder."""
    if not is_valid_name(filename):
        raise ValueError(
            f"invalid file name {filename!r}: it may not contain '/', '\\' or '..'"
        )

    send_message(sock, {"op": "DOWNLOAD", "filename": filename})

    reply = require_ok(read_message_header(sock))
    size = check_size(reply.get("size"), MAX_PAYLOAD_BYTES, "announced size")
    data = read_exactly_n_bytes(sock, size)

    DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)
    destination = DOWNLOAD_DIR / filename
    destination.write_bytes(data)
    print(f"Downloaded {filename} ({len(data)} bytes) -> {destination}")


def main():
    """Connect to the server and perform one upload or download."""
    args = build_parser().parse_args()

    try:
        validate_request(args)
        certfile = args.certfile or CERTS_DIR / f"{args.identity}-cert.pem"
        keyfile = args.keyfile or CERTS_DIR / f"{args.identity}-key.pem"
        context = build_tls_context(certfile, keyfile)
        with socket.create_connection(
            (args.host, args.port), timeout=SOCKET_TIMEOUT
        ) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=args.host) as sock:
                cert = sock.getpeercert()
                subject = dict(x[0] for x in cert["subject"])
                print(
                    f"{sock.version()} with {sock.cipher()[0]}, "
                    f"server authenticated as {subject.get('commonName')}"
                )
                if args.op == "UPLOAD":
                    do_upload(sock, Path(args.filename))
                else:
                    do_download(sock, args.filename)

    except ssl.SSLCertVerificationError as exc:
        print(
            f"Could not authenticate the server: {exc.verify_message}",
            file=sys.stderr,
        )
        return 1
    except ssl.SSLError as exc:
        print(f"TLS handshake failed: {exc}", file=sys.stderr)
        return 1
    except ConnectionError as exc:
        print(f"Connection to the server was lost: {exc}", file=sys.stderr)
        return 1
    except TimeoutError:
        print("The server did not respond in time.", file=sys.stderr)
        return 1
    except RuntimeError as exc:
        print(exc, file=sys.stderr)
        return 1
    except (OSError, ValueError, struct.error, json.JSONDecodeError) as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())