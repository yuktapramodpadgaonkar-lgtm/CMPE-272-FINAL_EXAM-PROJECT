#!/usr/bin/env python3
"""
Approach B — sender: plain TCP + X25519 + RSA-PSS signed certs + ChaCha20-Poly1305.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import socket
import struct
import sys
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, x25519
from cryptography.x509.oid import NameOID

from _proto import (
    CHUNK_SIZE,
    PROTO_MAGIC,
    PROTO_VERSION,
    aead_decrypt,
    aead_encrypt,
    derive_file_key,
    load_pem_cert,
    load_pem_rsa_key,
    nonce_for_index,
    read_u32_blob,
    rsa_pss_sign,
    rsa_pss_verify,
    sha256_file,
    u32be_pack,
    verify_child_cert,
    write_u32_blob,
)


MSG_META_AAD = b"META/1"
MSG_CTRL_AAD = b"SCTRL/1"
MSG_DATA_AAD_PREFIX = b"DATA/1"


def _peer_cn(cert: x509.Certificate) -> str:
    return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value


def main() -> int:
    ap = argparse.ArgumentParser(description="Approach B sender (app-layer AEAD)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5001)
    ap.add_argument("--certs-dir", type=Path, default=Path(__file__).resolve().parents[1] / "certs")
    ap.add_argument("--file", type=Path, required=True)
    args = ap.parse_args()

    certs_dir = args.certs_dir.resolve()
    path = args.file.resolve()
    if not path.is_file():
        print(f"[B sender] not a file: {path}", file=sys.stderr, flush=True)
        return 2

    ca = load_pem_cert(certs_dir / "ca.pem")
    send_priv_rsa = load_pem_rsa_key(certs_dir / "sender-key.pem")
    send_cert_pem = (certs_dir / "sender.pem").read_bytes()

    total_size = path.stat().st_size
    digest = sha256_file(path)

    cli_eph = x25519.X25519PrivateKey.generate()
    cli_pub = cli_eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    client_random = os.urandom(32)
    sign_payload_c = PROTO_MAGIC + bytes([PROTO_VERSION]) + client_random + cli_pub
    sig_c = rsa_pss_sign(send_priv_rsa, sign_payload_c)
    cli_hs = (
        PROTO_MAGIC
        + bytes([PROTO_VERSION])
        + client_random
        + cli_pub
        + u32be_pack(len(send_cert_pem))
        + send_cert_pem
        + u32be_pack(len(sig_c))
        + sig_c
    )

    raw = socket.create_connection((args.host, args.port), timeout=30)
    try:
        t0 = time.monotonic()
        write_u32_blob(raw, cli_hs)
        srv_hs = read_u32_blob(raw)

        off = 0
        magic = srv_hs[off : off + 7]
        off += 7
        if magic != PROTO_MAGIC:
            raise ValueError("bad magic from server")
        ver = srv_hs[off]
        off += 1
        if ver != PROTO_VERSION:
            raise ValueError("bad server version")
        server_random = srv_hs[off : off + 32]
        off += 32
        srv_pub_bytes = srv_hs[off : off + 32]
        off += 32
        c_len = struct.unpack(">I", srv_hs[off : off + 4])[0]
        off += 4
        srv_cert_pem = srv_hs[off : off + c_len]
        off += c_len
        s_len = struct.unpack(">I", srv_hs[off : off + 4])[0]
        off += 4
        sig_s = srv_hs[off : off + s_len]
        off += s_len
        if off != len(srv_hs):
            raise ValueError("trailing server HS bytes")

        peer_cert = x509.load_pem_x509_certificate(srv_cert_pem)
        verify_child_cert(ca, peer_cert)
        if _peer_cn(peer_cert) != "file-transfer-receiver":
            raise ValueError("wrong server cert role")
        peer_pub_rsa = peer_cert.public_key()
        if not isinstance(peer_pub_rsa, rsa.RSAPublicKey):
            raise TypeError("RSA server cert required")
        sign_payload_s = PROTO_MAGIC + bytes([PROTO_VERSION]) + client_random + server_random + srv_pub_bytes
        rsa_pss_verify(peer_pub_rsa, sign_payload_s, sig_s)
        srv_pub = x25519.X25519PublicKey.from_public_bytes(srv_pub_bytes)

        shared = cli_eph.exchange(srv_pub)
        k_meta = derive_file_key(shared, b"meta")
        k_file = derive_file_key(shared, b"payload")
        bind_digest = hashlib.sha256(client_random + server_random).digest()[:16]

        meta_plain = struct.pack(">Q", total_size) + digest + bind_digest
        meta_ct = aead_encrypt(k_meta, nonce_for_index(1), meta_plain, MSG_META_AAD)
        write_u32_blob(raw, meta_ct)

        ctrl_ct = read_u32_blob(raw)
        ctrl_plain = aead_decrypt(k_meta, nonce_for_index(2), ctrl_ct, MSG_CTRL_AAD)
        flag = ctrl_plain[:2]
        offset = struct.unpack(">Q", ctrl_plain[2:10])[0]
        if flag not in (b"GO", b"RS"):
            raise ValueError("bad control flag")
        if flag == b"GO" and offset != 0:
            raise ValueError("GO with non-zero offset")
        if offset > total_size:
            raise ValueError("resume offset beyond EOF")

        nonce_base = 3
        seq = 0
        sent = offset
        with path.open("rb") as f:
            if offset:
                f.seek(offset)
            while sent < total_size:
                to_read = min(CHUNK_SIZE, total_size - sent)
                chunk = f.read(to_read)
                if len(chunk) != to_read:
                    raise ValueError("short read from disk")
                nonce = nonce_for_index(nonce_base + seq)
                aad = MSG_DATA_AAD_PREFIX + struct.pack(">QQ", sent, total_size)
                ct = aead_encrypt(k_file, nonce, chunk, aad)
                write_u32_blob(raw, ct)
                seq += 1
                sent += len(chunk)

        dt = time.monotonic() - t0
        mib_s = (total_size / (1024 * 1024)) / dt if dt > 0 else 0.0
        print(f"[B sender] completed ({sent} bytes) throughput ~{mib_s:.2f} MiB/s", flush=True)
        return 0
    except Exception as e:
        print(f"[B sender] error: {e}", file=sys.stderr, flush=True)
        return 1
    finally:
        raw.close()


if __name__ == "__main__":
    raise SystemExit(main())
