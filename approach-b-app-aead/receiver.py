#!/usr/bin/env python3
"""
Approach B — receiver: plain TCP with X25519 ECDH, RSA-PSS signed handshake,
ChaCha20-Poly1305 per frame (application-layer AEAD).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import struct
import sys
import tempfile
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
    ap = argparse.ArgumentParser(description="Approach B receiver (app-layer AEAD)")
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=5001)
    ap.add_argument("--certs-dir", type=Path, default=Path(__file__).resolve().parents[1] / "certs")
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()

    certs_dir = args.certs_dir.resolve()
    ca = load_pem_cert(certs_dir / "ca.pem")
    recv_priv_rsa = load_pem_rsa_key(certs_dir / "receiver-key.pem")
    recv_cert_pem = (certs_dir / "receiver.pem").read_bytes()

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.bind, args.port))
    listener.listen(1)
    print(f"[B receiver] listening on {args.bind}:{args.port}", flush=True)

    raw, _ = listener.accept()
    try:
        hs = read_u32_blob(raw)
        server_random = os.urandom(32)
        srv_eph = x25519.X25519PrivateKey.generate()
        srv_pub = srv_eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

        off = 0
        if len(hs) < 7 + 1 + 32 + 32 + 4:
            raise ValueError("short client handshake")
        magic = hs[off : off + 7]
        off += 7
        if magic != PROTO_MAGIC:
            raise ValueError("bad magic")
        ver = hs[off]
        off += 1
        if ver != PROTO_VERSION:
            raise ValueError("bad version")
        client_random = hs[off : off + 32]
        off += 32
        cli_pub_bytes = hs[off : off + 32]
        off += 32
        c_len = struct.unpack(">I", hs[off : off + 4])[0]
        off += 4
        cli_cert_pem = hs[off : off + c_len]
        off += c_len
        s_len = struct.unpack(">I", hs[off : off + 4])[0]
        off += 4
        cli_sig = hs[off : off + s_len]
        off += s_len
        if off != len(hs):
            raise ValueError("trailing bytes in client HS")

        peer_cert = x509.load_pem_x509_certificate(cli_cert_pem)
        verify_child_cert(ca, peer_cert)
        if _peer_cn(peer_cert) != "file-transfer-sender":
            raise ValueError("wrong peer cert role")
        peer_pub_rsa = peer_cert.public_key()
        if not isinstance(peer_pub_rsa, rsa.RSAPublicKey):
            raise TypeError("RSA peer cert required")
        sign_payload_c = PROTO_MAGIC + bytes([PROTO_VERSION]) + client_random + cli_pub_bytes
        rsa_pss_verify(peer_pub_rsa, sign_payload_c, cli_sig)
        cli_pub = x25519.X25519PublicKey.from_public_bytes(cli_pub_bytes)

        sign_payload_s = PROTO_MAGIC + bytes([PROTO_VERSION]) + client_random + server_random + srv_pub
        sig_s = rsa_pss_sign(recv_priv_rsa, sign_payload_s)
        srv_hs = (
            PROTO_MAGIC
            + bytes([PROTO_VERSION])
            + server_random
            + srv_pub
            + u32be_pack(len(recv_cert_pem))
            + recv_cert_pem
            + u32be_pack(len(sig_s))
            + sig_s
        )
        write_u32_blob(raw, srv_hs)

        shared = srv_eph.exchange(cli_pub)
        k_meta = derive_file_key(shared, b"meta")
        k_file = derive_file_key(shared, b"payload")

        bind_digest = hashlib.sha256(client_random + server_random).digest()[:16]

        meta_ct = read_u32_blob(raw)
        meta_pt = aead_decrypt(k_meta, nonce_for_index(1), meta_ct, MSG_META_AAD)
        total_size = struct.unpack(">Q", meta_pt[:8])[0]
        expected_digest = meta_pt[8:40]
        bind_recv = meta_pt[40:56]
        if bind_recv != bind_digest:
            raise ValueError("session binding mismatch")

        partial_path = args.output.with_suffix(args.output.suffix + ".partial")
        meta_p = partial_path.with_suffix(partial_path.suffix + ".meta.json")

        offset = 0
        h = hashlib.sha256()
        if partial_path.exists() and meta_p.exists():
            meta = json.loads(meta_p.read_text(encoding="utf-8"))
            if int(meta["expected_size"]) == total_size and bytes.fromhex(meta["expected_sha256"]) == expected_digest:
                offset = int(meta["bytes_written"])
                with partial_path.open("rb") as pf:
                    rem = offset
                    while rem > 0:
                        block = pf.read(min(CHUNK_SIZE, rem))
                        if not block:
                            raise ValueError("short partial")
                        h.update(block)
                        rem -= len(block)
            else:
                partial_path.unlink(missing_ok=True)
                meta_p.unlink(missing_ok=True)
                offset = 0
                h = hashlib.sha256()
        else:
            partial_path.unlink(missing_ok=True)
            meta_p.unlink(missing_ok=True)

        ctrl_plain = (b"RS" if offset else b"GO") + struct.pack(">Q", offset)
        ctrl_ct = aead_encrypt(k_meta, nonce_for_index(2), ctrl_plain, MSG_CTRL_AAD)
        write_u32_blob(raw, ctrl_ct)

        nonce_base = 3
        seq = 0
        with partial_path.open("r+b" if offset else "wb") as outf:
            if offset:
                outf.seek(offset)
            received = offset
            while received < total_size:
                frame = read_u32_blob(raw)
                nonce = nonce_for_index(nonce_base + seq)
                aad = MSG_DATA_AAD_PREFIX + struct.pack(">QQ", received, total_size)
                pt = aead_decrypt(k_file, nonce, frame, aad)
                seq += 1
                if len(pt) == 0 or len(pt) > CHUNK_SIZE:
                    raise ValueError("bad chunk plaintext size")
                h.update(pt)
                outf.write(pt)
                received += len(pt)
                outf.flush()
                os.fsync(outf.fileno())
                meta_p.write_text(
                    json.dumps(
                        {
                            "expected_size": total_size,
                            "expected_sha256": expected_digest.hex(),
                            "bytes_written": received,
                        }
                    ),
                    encoding="utf-8",
                )

        if received != total_size:
            raise ValueError("size mismatch")

        digest = h.digest()
        if digest != expected_digest:
            raise ValueError("SHA-256 mismatch")

        args.output.unlink(missing_ok=True)
        fd, tmp_final = tempfile.mkstemp(prefix=".secft-final-", dir=str(args.output.parent))
        os.close(fd)
        tmp_final_p = Path(tmp_final)
        try:
            partial_path.replace(tmp_final_p)
            tmp_final_p.replace(args.output)
        except Exception:
            tmp_final_p.unlink(missing_ok=True)
            raise
        meta_p.unlink(missing_ok=True)
        print("[B receiver] OK - file verified and installed", flush=True)
        return 0
    except Exception as e:
        print(f"[B receiver] error: {e}", file=sys.stderr, flush=True)
        partial_path = args.output.with_suffix(args.output.suffix + ".partial")
        meta_p = partial_path.with_suffix(partial_path.suffix + ".meta.json")
        partial_path.unlink(missing_ok=True)
        meta_p.unlink(missing_ok=True)
        args.output.unlink(missing_ok=True)
        return 1
    finally:
        raw.close()
        listener.close()


if __name__ == "__main__":
    raise SystemExit(main())
