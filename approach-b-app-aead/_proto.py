"""Shared framing and crypto helpers for Approach B (plain TCP + AEAD)."""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

CHUNK_SIZE = 1024 * 1024  # 1 MiB
PROTO_MAGIC = b"SECFTB1"
PROTO_VERSION = 1


def read_exact(sock, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("connection closed")
        buf.extend(chunk)
    return bytes(buf)


def send_all(sock, data: bytes) -> None:
    view = memoryview(data)
    while len(view):
        sent = sock.send(view)
        view = view[sent:]


def u32be_pack(n: int) -> bytes:
    if n < 0 or n >= 2**32:
        raise ValueError("u32 out of range")
    return struct.pack(">I", n)


def read_u32_blob(sock) -> bytes:
    hdr = read_exact(sock, 4)
    ln = struct.unpack(">I", hdr)[0]
    if ln > 16 * 1024 * 1024:
        raise ValueError("oversized framed blob")
    return read_exact(sock, ln)


def write_u32_blob(sock, payload: bytes) -> None:
    send_all(sock, u32be_pack(len(payload)) + payload)


def load_pem_cert(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


def load_pem_rsa_key(path: Path) -> rsa.RSAPrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError("RSA private key required")
    return key


def verify_child_cert(ca: x509.Certificate, peer: x509.Certificate) -> None:
    if peer.issuer != ca.subject:
        raise ValueError("cert issuer mismatch")
    pubkey = ca.public_key()
    if not isinstance(pubkey, rsa.RSAPublicKey):
        raise TypeError("CA must be RSA for this demo")
    pubkey.verify(
        peer.signature,
        peer.tbs_certificate_bytes,
        asym_padding.PKCS1v15(),
        peer.signature_hash_algorithm,
    )


def rsa_pss_sign(priv: rsa.RSAPrivateKey, message: bytes) -> bytes:
    return priv.sign(
        message,
        asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def rsa_pss_verify(pub: rsa.RSAPublicKey, message: bytes, signature: bytes) -> None:
    pub.verify(
        signature,
        message,
        asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def derive_file_key(shared: bytes, label: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"cmpe272-approach-b",
        info=label,
    )
    return hkdf.derive(shared)


def aead_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    return ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)


def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)


def nonce_for_index(idx: int) -> bytes:
    if idx < 0 or idx >= 2**96:
        raise ValueError("nonce index out of range")
    return idx.to_bytes(12, "big")


def sha256_file(path: Path) -> bytes:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            block = f.read(CHUNK_SIZE)
            if not block:
                break
            h.update(block)
    return h.digest()
