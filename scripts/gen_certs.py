#!/usr/bin/env python3
"""Generate a small CA and mTLS cert pair for Approach A (TLS) and trust anchors for Approach B."""
from __future__ import annotations

import datetime
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

VALID_DAYS = 825
KEY_SIZE = 2048


def _write_pem(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def main() -> None:
    root = Path(__file__).resolve().parents[1] / "certs"
    now = datetime.datetime.now(datetime.timezone.utc)

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=KEY_SIZE)
    ca_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "CMPE272 Demo CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CMPE272"),
        ]
    )
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=VALID_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    san = x509.SubjectAlternativeName(
        [
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        ]
    )

    def issue_entity(common_name: str, server_auth: bool, client_auth: bool) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
        key = rsa.generate_private_key(public_exponent=65537, key_size=KEY_SIZE)
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CMPE272"),
            ]
        )
        ext_key_usage = []
        if server_auth:
            ext_key_usage.append(ExtendedKeyUsageOID.SERVER_AUTH)
        if client_auth:
            ext_key_usage.append(ExtendedKeyUsageOID.CLIENT_AUTH)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=VALID_DAYS))
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.ExtendedKeyUsage(ext_key_usage), critical=False)
            .add_extension(san, critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        return key, cert

    recv_key, recv_cert = issue_entity("file-transfer-receiver", server_auth=True, client_auth=False)
    send_key, send_cert = issue_entity("file-transfer-sender", server_auth=False, client_auth=True)

    _write_pem(root / "ca.pem", ca_cert.public_bytes(serialization.Encoding.PEM))
    _write_pem(root / "ca-key.pem", ca_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))

    _write_pem(root / "receiver.pem", recv_cert.public_bytes(serialization.Encoding.PEM))
    _write_pem(root / "receiver-key.pem", recv_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))

    _write_pem(root / "sender.pem", send_cert.public_bytes(serialization.Encoding.PEM))
    _write_pem(root / "sender-key.pem", send_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))

    print(f"Wrote PEM material under {root}")


if __name__ == "__main__":
    main()
