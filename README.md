# Secure File Transfer

A client-server file transfer system built on mutually authenticated TLS, developed as a Network Security course project.

Both endpoints prove their identity with X.509 certificates issued by a project-internal certificate authority. TLS 1.2 is the lowest accepted version; TLS 1.3 is negotiated whenever both endpoints support it. The channel provides confidentiality and integrity in transit; SHA-256 digests, recorded at upload and verified again at download, extend integrity to files at rest. Each authenticated identity is confined to its own storage namespace.

## Components

| Path | Role |
|---|---|
| `certs/generate_certs.py` | Builds the PKI: the certificate authority, the server certificate and one certificate per client. Run once, offline. |
| `server/server.py` | Listens on a single TCP port, authenticates clients, and manages per-identity storage. |
| `client/client.py` | Performs one upload or download and exits. |

No third-party dependencies at runtime — only the Python standard library, 3.10 or later. `cryptography` is required by the PKI generator alone.

## Protocol

Two operations over a custom framed protocol: a 4-byte big-endian length prefix, a UTF-8 JSON header, and an optional binary payload.

- **UPLOAD** — the client sends filename, size and SHA-256 digest, followed by the file. The server verifies the digest before writing anything to disk, and refuses a name that already exists rather than overwriting it.
- **DOWNLOAD** — the client sends a filename and receives size, digest and payload. Both the server and the client verify the digest independently.

One request per connection. Files are held in memory during transfer, so a payload is capped at 100 MiB.

## Usage

Requires Python 3.10 or later. Install the dependency needed by the PKI generator, then build the PKI:

```bash
pip install -r requirements.txt
python3 certs/generate_certs.py
```

The generated server certificate covers `localhost`, `127.0.0.1` and the addresses of the machine the generator runs on. To reach the server from another host, run the generator on the server machine — or add a name explicitly with `--server-host` — and copy `ca-cert.pem` together with the client's own certificate and key to the client machine. The CA private key never leaves the server host.

Start the server:

```bash
python3 server/server.py
```

Transfer a file:

```bash
python3 client/client.py UPLOAD /path/to/file.txt --identity alice
python3 client/client.py DOWNLOAD file.txt --identity alice
```

Uploaded files are stored under `server/storage/<common-name>/`, with digests in `.meta/`. Downloads are written to `client/downloads/`. Each identity sees only its own namespace: a file uploaded by `alice` is reported as absent to `bob`.

Run either program with `--help` for the full set of options, including alternative hosts, ports and certificate paths.

## Security scope

The three stated objectives are authentication, confidentiality and integrity. Availability is not among them, and the server is single-threaded.

The server is assumed to be trusted for storage: recorded digests are unsigned, so the integrity check covers accidental corruption and naive tampering rather than a compromised host. Private keys are written with restrictive permissions but are not encrypted at rest. There is no certificate revocation mechanism; a compromised principal remains valid until its certificate expires.

## Repository

Certificates and private keys are not versioned. Cloning this repository gives you the procedure that builds a PKI, not the PKI itself — run the generator to create your own.
