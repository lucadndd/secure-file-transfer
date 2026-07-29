"""
Generate the X.509 material used by the project.
"""

import datetime
import os
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

CERTS_DIR = Path(__file__).resolve().parent
CA_KEY_PATH = CERTS_DIR / "ca-key.pem"
CA_CERT_PATH = CERTS_DIR / "ca-cert.pem"

CURVE = ec.SECP256R1()
CA_VALIDITY_DAYS = 3650
CLOCK_SKEW = datetime.timedelta(minutes=5)

CA_NAME = x509.Name(
    [
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure File Transfer"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Secure File Transfer Root CA"),
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


def main():
    """
    Generate the CA.
    """
    ca_key = generate_key()
    ca_cert = build_ca_certificate(ca_key)
    write_private_key(CA_KEY_PATH, ca_key)
    write_certificate(CA_CERT_PATH, ca_cert)
    print(f"wrote {CA_KEY_PATH}")
    print(f"wrote {CA_CERT_PATH}")


if __name__ == "__main__":
    main()