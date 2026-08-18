"""
Generate the X.509 material used by the project.
"""
import argparse
import datetime
import ipaddress
import os
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CERTS_DIR = Path(__file__).resolve().parent
CA_KEY_PATH = CERTS_DIR / "ca-key.pem"
CA_CERT_PATH = CERTS_DIR / "ca-cert.pem"
SERVER_KEY_PATH = CERTS_DIR / "server-key.pem"
SERVER_CERT_PATH = CERTS_DIR / "server-cert.pem"

CURVE = ec.SECP256R1()
CA_VALIDITY_DAYS = 3650
LEAF_VALIDITY_DAYS = 365
CLOCK_SKEW = datetime.timedelta(minutes=5)

DEFAULT_SERVER_HOSTS = ["localhost", "127.0.0.1"]

CA_NAME = x509.Name(
    [
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure File Transfer"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Secure File Transfer Root CA"),
    ]
)

SERVER_NAME = x509.Name(
    [
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure File Transfer"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ]
)


CLIENT_NAMES = ["alice", "bob"]


def now():
    """
    Return the current UTC time.

    Returns:
        datetime.datetime: timezone-aware current time.
    """
    return datetime.datetime.now(datetime.timezone.utc)


def generate_key():
    """
    Generate an ECDSA private key.

    Returns:
        ec.EllipticCurvePrivateKey: a new key on CURVE.
    """
    return ec.generate_private_key(CURVE)


def write_private_key(path, key):
    """
    Write an unencrypted PKCS#8 PEM key.

    Args:
        path (Path): destination file.
        key: private key to serialize.
    """
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    os.chmod(path, 0o600)


def write_certificate(path, cert):
    """
    Write a certificate in PEM form.

    Args:
        path (Path): destination file.
        cert (x509.Certificate): certificate to serialize.
    """
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def build_san(hosts):
    """
    Build a subject alternative name extension from a list of hosts.

    Args:
        hosts (list[str]): host names or IP addresses.

    Returns:
        x509.SubjectAlternativeName: the extension value.
    """
    entries = []
    for host in hosts:
        try:
            entries.append(x509.IPAddress(ipaddress.ip_address(host)))
        except ValueError:
            entries.append(x509.DNSName(host))
    return x509.SubjectAlternativeName(entries)


def ca_key_usage():
    """
    Build the key usage extension for a certificate authority.

    Returns:
        x509.KeyUsage: signing of certificates and revocation lists only.
    """
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False,
    )


def leaf_key_usage():
    """
    Build the key usage extension for an end-entity certificate.

    Returns:
        x509.KeyUsage: digital signature only, which is what an ECDSA key
        needs for the TLS handshake.
    """
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )


def authority_key_identifier(issuer_cert):
    """
    Derive the authority key identifier from the issuer certificate.

    Args:
        issuer_cert (x509.Certificate): certificate of the issuing CA.

    Returns:
        x509.AuthorityKeyIdentifier: the extension value.
    """
    ski = issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    return x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski.value)


def build_ca_certificate(ca_key):
    """
    Build the self-signed root certificate.

    Args:
        ca_key: private key of the CA.

    Returns:
        x509.Certificate: the self-signed CA certificate.
    """
    issued_at = now()
    return (
        x509.CertificateBuilder()
        .subject_name(CA_NAME)
        .issuer_name(CA_NAME)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(issued_at - CLOCK_SKEW)
        .not_valid_after(issued_at + datetime.timedelta(days=CA_VALIDITY_DAYS))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0), critical=True
        )
        .add_extension(ca_key_usage(), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )


def build_leaf_certificate(subject, subject_key, ca_key, ca_cert, purpose, san=None):
    """
    Build an end-entity certificate signed by the CA.

    Args:
        subject (x509.Name): distinguished name of the subject.
        subject_key: private key of the subject; only the public part is used.
        ca_key: private key of the CA, used to sign.
        ca_cert (x509.Certificate): CA certificate, used as issuer.
        purpose (x509.ObjectIdentifier): single extended key usage OID.
        san (x509.SubjectAlternativeName): names the certificate is valid
            for, or None to omit the extension.

    Returns:
        x509.Certificate: the signed end-entity certificate.
    """
    issued_at = now()
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(issued_at - CLOCK_SKEW)
        .not_valid_after(issued_at + datetime.timedelta(days=LEAF_VALIDITY_DAYS))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .add_extension(leaf_key_usage(), critical=True)
        .add_extension(x509.ExtendedKeyUsage([purpose]), critical=False)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()),
            critical=False,
        )
        .add_extension(authority_key_identifier(ca_cert), critical=False)
    )
    if san is not None:
        builder = builder.add_extension(san, critical=False)
    return builder.sign(ca_key, hashes.SHA256())


def build_server_certificate(server_key, ca_key, ca_cert, hosts):
    """
    Build the server certificate signed by the CA.

    Args:
        server_key: private key of the server.
        ca_key: private key of the CA, used to sign.
        ca_cert (x509.Certificate): CA certificate, used as issuer.
        hosts (list[str]): names and addresses the certificate is valid
            for.

    Returns:
        x509.Certificate: the server certificate.
    """
    return build_leaf_certificate(
        SERVER_NAME,
        server_key,
        ca_key,
        ca_cert,
        ExtendedKeyUsageOID.SERVER_AUTH,
        build_san(hosts),
    )


def client_name(cn):
    """
    Build the distinguished name of a client.

    Args:
        cn (str): common name identifying the client.

    Returns:
        x509.Name: distinguished name for the client certificate.
    """
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure File Transfer"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )


def client_key_path(cn):
    """
    Return the file the private key of a client is written to.

    Args:
        cn (str): common name identifying the client.

    Returns:
        Path: destination file.
    """
    return CERTS_DIR / f"{cn}-key.pem"


def client_cert_path(cn):
    """
    Return the file the certificate of a client is written to.

    Args:
        cn (str): common name identifying the client.

    Returns:
        Path: destination file.
    """
    return CERTS_DIR / f"{cn}-cert.pem"


def build_client_certificate(cn, client_key, ca_key, ca_cert):
    """
    Build the client certificate signed by the CA.

    Args:
        cn (str): common name identifying the client.
        client_key: private key of the client.
        ca_key: private key of the CA, used to sign.
        ca_cert (x509.Certificate): CA certificate, used as issuer.

    Returns:
        x509.Certificate: the client certificate.
    """
    return build_leaf_certificate(
        client_name(cn),
        client_key,
        ca_key,
        ca_cert,
        ExtendedKeyUsageOID.CLIENT_AUTH,
    )


def build_parser():
    """
    Build the command-line argument parser.

    Returns:
        argparse.ArgumentParser: parser accepting repeated --server-host.
    """
    parser = argparse.ArgumentParser(
        description="Generate the CA, the server certificate and one "
        "certificate per client."
    )
    parser.add_argument(
        "--server-host",
        action="append",
        default=None,
        metavar="NAME_OR_IP",
        help="Extra name or address the server certificate is valid for; "
        "repeat for several. Always includes "
        f"{' and '.join(DEFAULT_SERVER_HOSTS)}.",
    )
    return parser


def server_hosts(extra):
    """
    Return the names the server certificate is issued for.

    Args:
        extra (list[str] | None): additional names or addresses.

    Returns:
        list[str]: the defaults followed by the extras, without
        duplicates.
    """
    hosts = list(DEFAULT_SERVER_HOSTS)
    for host in extra or []:
        if host not in hosts:
            hosts.append(host)
    return hosts


def main():
    """
    Generate the CA, the server certificate and one certificate per client.
    """
    args = build_parser().parse_args()
    hosts = server_hosts(args.server_host)

    ca_key = generate_key()
    ca_cert = build_ca_certificate(ca_key)
    write_private_key(CA_KEY_PATH, ca_key)
    write_certificate(CA_CERT_PATH, ca_cert)
    print(f"wrote {CA_KEY_PATH}")
    print(f"wrote {CA_CERT_PATH}")

    server_key = generate_key()
    server_cert = build_server_certificate(server_key, ca_key, ca_cert, hosts)
    write_private_key(SERVER_KEY_PATH, server_key)
    write_certificate(SERVER_CERT_PATH, server_cert)
    print(f"wrote {SERVER_KEY_PATH}")
    print(f"wrote {SERVER_CERT_PATH} valid for {', '.join(hosts)}")

    for cn in CLIENT_NAMES:
        client_key = generate_key()
        client_cert = build_client_certificate(cn, client_key, ca_key, ca_cert)
        write_private_key(client_key_path(cn), client_key)
        write_certificate(client_cert_path(cn), client_cert)
        print(f"wrote {client_key_path(cn)}")
        print(f"wrote {client_cert_path(cn)}")


if __name__ == "__main__":
    main()