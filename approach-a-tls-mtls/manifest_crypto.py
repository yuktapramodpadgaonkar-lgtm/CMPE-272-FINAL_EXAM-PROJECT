"""RSA-PSS-SHA256 signatures for Approach A FHDR manifest (explicit auth beyond TLS bytes)."""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa


def transfer_file_id(digest: bytes, total_size: int) -> bytes:
    """16-byte deterministic id for checkpoint binding across sessions."""
    return hashlib.sha256(digest + struct.pack(">Q", total_size)).digest()[:16]


def load_rsa_private_key(path: Path) -> rsa.RSAPrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError("RSA private key required")
    return key


def load_der_peer_cert(der: bytes) -> x509.Certificate:
    return x509.load_der_x509_certificate(der)


def sign_manifest(priv: rsa.RSAPrivateKey, message: bytes) -> bytes:
    return priv.sign(
        message,
        asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def verify_manifest(pub: rsa.RSAPublicKey, message: bytes, signature: bytes) -> None:
    pub.verify(
        signature,
        message,
        asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def peer_public_key_from_der(der: bytes) -> rsa.RSAPublicKey:
    cert = load_der_peer_cert(der)
    pub = cert.public_key()
    if not isinstance(pub, rsa.RSAPublicKey):
        raise TypeError("peer must use RSA cert for manifest verification in this demo")
    return pub
