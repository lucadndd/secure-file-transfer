"""
Generate the X.509 material used by the project.
"""

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

SERVER_HOSTS = ["localhost", "127.0.0.1"]

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


def build_server_certificate(server_key, ca_key, ca_cert):
    """
    Build the server certificate signed by the CA.

    Args:
        server_key: private key of the server.
        ca_key: private key of the CA, used to sign.
        ca_cert (x509.Certificate): CA certificate, used as issuer.

    Returns:
        x509.Certificate: the server certificate.
    """
    issued_at = now()
    return (
        x509.CertificateBuilder()
        .subject_name(SERVER_NAME)
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(issued_at - CLOCK_SKEW)
        .not_valid_after(issued_at + datetime.timedelta(days=LEAF_VALIDITY_DAYS))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .add_extension(leaf_key_usage(), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(build_san(SERVER_HOSTS), critical=False)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()),
            critical=False,
        )
        .add_extension(authority_key_identifier(ca_cert), critical=False)
        .sign(ca_key, hashes.SHA256())
    )


def main():
    """
    Generate the CA and the server certificate.
    """
    ca_key = generate_key()
    ca_cert = build_ca_certificate(ca_key)
    write_private_key(CA_KEY_PATH, ca_key)
    write_certificate(CA_CERT_PATH, ca_cert)
    print(f"wrote {CA_KEY_PATH}")
    print(f"wrote {CA_CERT_PATH}")

    server_key = generate_key()
    server_cert = build_server_certificate(server_key, ca_key, ca_cert)
    write_private_key(SERVER_KEY_PATH, server_key)
    write_certificate(SERVER_CERT_PATH, server_cert)
    print(f"wrote {SERVER_KEY_PATH}")
    print(f"wrote {SERVER_CERT_PATH}")


if __name__ == "__main__":
    main()