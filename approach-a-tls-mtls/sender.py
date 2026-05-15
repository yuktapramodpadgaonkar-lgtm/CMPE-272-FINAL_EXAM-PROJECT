#!/usr/bin/env python3
"""
Approach A — sender: mutually-authenticated TLS client.

Streams a file in CHUNK_SIZE plaintext segments over TLS; receiver verifies
SHA-256 of plaintext. Supports resuming when receiver reports an offset.

The file manifest (expected SHA-256, size, session binding) is sent inside the
mTLS tunnel and RSA-PSS-SHA256 signed so it is bound to the sender certificate,
not only protected by TLS record encryption.
"""
from __future__ import annotations

import argparse
import hashlib
import socket
import ssl
import struct
import sys
import time
from pathlib import Path

from manifest_crypto import load_rsa_private_key, sign_manifest, transfer_file_id

CHUNK_SIZE = 1024 * 1024  # 1 MiB (must match receiver)
PROTO_MAGIC = b"SECFTA1"
MSG_READY = b"READY01"
MSG_FHDR2 = b"FHDR002"
MSG_GO = b"GO00001"
MSG_RESUME = b"RESUM01"
MSG_CHNK = b"CHNK001"
MSG_DONE = b"DONE001"


def read_exact(sock: ssl.SSLSocket, n: int) -> bytes:
    out = bytearray()
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            raise EOFError("peer closed socket before sending expected bytes")
        out.extend(chunk)
    return bytes(out)


def send_all(sock: ssl.SSLSocket, data: bytes) -> None:
    view = memoryview(data)
    while len(view):
        n = sock.send(view)
        view = view[n:]


def sha256_file(path: Path) -> bytes:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            block = f.read(CHUNK_SIZE)
            if not block:
                break
            h.update(block)
    return h.digest()


def build_ssl_client_context(certs_dir: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_verify_locations(cafile=str(certs_dir / "ca.pem"))
    ctx.load_cert_chain(certfile=str(certs_dir / "sender.pem"), keyfile=str(certs_dir / "sender-key.pem"))
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    return ctx


def main() -> int:
    ap = argparse.ArgumentParser(description="Approach A sender (mTLS)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--server-name", default=None, help="TLS hostname verification (defaults to --host)")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--certs-dir", type=Path, default=Path(__file__).resolve().parents[1] / "certs")
    ap.add_argument("--file", type=Path, required=True, help="File to send")
    args = ap.parse_args()

    certs_dir = args.certs_dir.resolve()
    path = args.file.resolve()
    if not path.is_file():
        print(f"[A sender] not a file: {path}", file=sys.stderr, flush=True)
        return 2

    total_size = path.stat().st_size
    digest = sha256_file(path)
    file_id = transfer_file_id(digest, total_size)
    sign_key = load_rsa_private_key(certs_dir / "sender-key.pem")

    ctx = build_ssl_client_context(certs_dir)
    raw = socket.create_connection((args.host, args.port), timeout=30)
    server_name = args.server_name or args.host
    tls_sock: ssl.SSLSocket | None = None
    try:
        tls_sock = ctx.wrap_socket(raw, server_hostname=server_name)
        t0 = time.monotonic()
        send_all(tls_sock, PROTO_MAGIC)
        ready = read_exact(tls_sock, len(MSG_READY))
        if ready != MSG_READY:
            raise ValueError("expected READY from receiver")
        server_nonce = read_exact(tls_sock, 16)

        manifest = file_id + struct.pack(">Q", total_size) + digest + server_nonce
        sig = sign_manifest(sign_key, manifest)
        send_all(
            tls_sock,
            MSG_FHDR2 + manifest + struct.pack(">I", len(sig)) + sig,
        )

        ctrl = read_exact(tls_sock, len(MSG_GO))
        resume_data = read_exact(tls_sock, 8)
        offset = 0
        if ctrl == MSG_RESUME:
            offset = struct.unpack(">Q", resume_data)[0]
        elif ctrl == MSG_GO:
            if struct.unpack(">Q", resume_data)[0] != 0:
                raise ValueError("unexpected GO payload")
        else:
            raise ValueError("expected GO or RESUME control message")

        if offset > total_size:
            raise ValueError("receiver requested offset beyond EOF")

        with path.open("rb") as f:
            if offset:
                f.seek(offset)
            sent = offset
            while sent < total_size:
                to_read = min(CHUNK_SIZE, total_size - sent)
                chunk = f.read(to_read)
                if len(chunk) != to_read:
                    raise ValueError("short read from disk")
                send_all(tls_sock, MSG_CHNK + struct.pack(">I", len(chunk)) + chunk)
                sent += len(chunk)

        send_all(tls_sock, MSG_DONE)
        dt = time.monotonic() - t0
        mib_s = (total_size / (1024 * 1024)) / dt if dt > 0 else 0.0
        print(f"[A sender] completed ({sent} bytes) throughput ~{mib_s:.2f} MiB/s", flush=True)
        return 0
    except Exception as e:
        print(f"[A sender] error: {e}", file=sys.stderr, flush=True)
        return 1
    finally:
        if tls_sock is not None:
            tls_sock.close()
        else:
            try:
                raw.close()
            except OSError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
