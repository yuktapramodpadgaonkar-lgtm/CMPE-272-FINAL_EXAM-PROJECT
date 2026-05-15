#!/usr/bin/env python3
"""
Approach A — receiver: mutually authenticated TLS (transport-layer security).

Listens on TCP, requires client certificate, streams plaintext chunks over TLS,
verifies end-to-end SHA-256 of plaintext, supports resumable offsets.

FHDR manifest (size, digest, session binding) is sent inside the TLS tunnel and
RSA-PSS-SHA256 signed by the sender so the expected file hash is bound to the
authenticated client identity, not only to TLS record integrity.
"""
from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import socket
import ssl
import struct
import sys
import tempfile
import time
from pathlib import Path

from manifest_crypto import peer_public_key_from_der, transfer_file_id, verify_manifest

# Application chunk size (plaintext per TLS write). TLS adds its own AEAD records.
CHUNK_SIZE = 1024 * 1024  # 1 MiB — balances syscall overhead vs memory pressure
PROTO_MAGIC = b"SECFTA1"
MSG_READY = b"READY01"
MSG_FHDR2 = b"FHDR002"  # signed manifest (replaces unsigned FHDR001)
MSG_GO = b"GO00001"
MSG_RESUME = b"RESUM01"
MSG_CHNK = b"CHNK001"
MSG_DONE = b"DONE001"

MAX_MANIFEST_SIG = 512


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


def meta_path_for(partial: Path) -> Path:
    return partial.with_suffix(partial.suffix + ".meta.json")


def build_ssl_server_context(certs_dir: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=str(certs_dir / "receiver.pem"), keyfile=str(certs_dir / "receiver-key.pem"))
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=str(certs_dir / "ca.pem"))
    return ctx


def _is_likely_disconnect(exc: BaseException) -> bool:
    if isinstance(exc, (EOFError, BrokenPipeError, ConnectionAbortedError, ConnectionResetError)):
        return True
    if isinstance(exc, ssl.SSLEOFError):
        return True
    if isinstance(exc, OSError):
        if getattr(exc, "winerror", None) == 10054:
            return True
        if exc.errno in (
            errno.ECONNRESET,
            errno.ECONNABORTED,
            errno.EPIPE,
            errno.ETIMEDOUT,
        ):
            return True
    return False


def _quarantine(path: Path, suffix: str) -> None:
    if not path.exists():
        return
    dest = path.with_name(path.name + suffix + str(int(time.time())))
    try:
        path.rename(dest)
    except OSError:
        path.unlink(missing_ok=True)


def main() -> int:
    ap = argparse.ArgumentParser(description="Approach A receiver (mTLS)")
    ap.add_argument("--bind", default="0.0.0.0", help="Listen address")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--certs-dir", type=Path, default=Path(__file__).resolve().parents[1] / "certs")
    ap.add_argument("--output", type=Path, required=True, help="Final output path (written via temp + rename)")
    args = ap.parse_args()

    certs_dir = args.certs_dir.resolve()
    ctx = build_ssl_server_context(certs_dir)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.bind, args.port))
    listener.listen(1)
    print(f"[A receiver] listening on {args.bind}:{args.port}", flush=True)

    tls_sock: ssl.SSLSocket | None = None
    raw: socket.socket | None = None
    exit_code = 1
    partial_path = args.output.with_suffix(args.output.suffix + ".partial")
    meta_p = meta_path_for(partial_path)

    try:
        raw, _ = listener.accept()
        try:
            tls_sock = ctx.wrap_socket(raw, server_side=True)
        except ssl.SSLError as e:
            print(f"[A receiver] TLS handshake failed: {e}", file=sys.stderr, flush=True)
            return 2
        raw = None

        magic = read_exact(tls_sock, len(PROTO_MAGIC))
        if magic != PROTO_MAGIC:
            raise ValueError("bad protocol magic")

        server_nonce = os.urandom(16)
        send_all(tls_sock, MSG_READY + server_nonce)

        fhdr = read_exact(tls_sock, len(MSG_FHDR2))
        if fhdr != MSG_FHDR2:
            raise ValueError("expected FHDR002 signed manifest")

        file_id = read_exact(tls_sock, 16)
        total_size = struct.unpack(">Q", read_exact(tls_sock, 8))[0]
        expected_digest = read_exact(tls_sock, 32)
        echo_nonce = read_exact(tls_sock, 16)
        if echo_nonce != server_nonce:
            raise ValueError("FHDR session binding mismatch")

        if file_id != transfer_file_id(expected_digest, total_size):
            raise ValueError("file_id does not bind digest+size")

        sig_len = struct.unpack(">I", read_exact(tls_sock, 4))[0]
        if sig_len == 0 or sig_len > MAX_MANIFEST_SIG:
            raise ValueError("bad manifest signature length")
        signature = read_exact(tls_sock, sig_len)

        peer_der = tls_sock.getpeercert(binary_form=True)
        if not peer_der:
            raise ValueError("missing client certificate after mTLS")
        manifest_bytes = file_id + struct.pack(">Q", total_size) + expected_digest + echo_nonce
        pub = peer_public_key_from_der(peer_der)
        verify_manifest(pub, manifest_bytes, signature)

        offset = 0
        h = hashlib.sha256()

        if partial_path.exists() and meta_p.exists():
            meta = json.loads(meta_p.read_text(encoding="utf-8"))
            if int(meta.get("chunk_size", -1)) != CHUNK_SIZE:
                raise ValueError("checkpoint chunk_size mismatch — refusing resume")
            if meta.get("file_id") != file_id.hex():
                send_all(tls_sock, MSG_GO + struct.pack(">Q", 0))
                partial_path.unlink(missing_ok=True)
                meta_p.unlink(missing_ok=True)
                offset = 0
                h = hashlib.sha256()
            elif (
                int(meta["expected_size"]) == total_size
                and bytes.fromhex(meta["expected_sha256"]) == expected_digest
            ):
                offset = int(meta["bytes_written"])
                stored_prefix = meta.get("prefix_sha256")
                if offset > 0:
                    if not stored_prefix:
                        raise ValueError("missing prefix_sha256 for resume — restart transfer")
                    print(f"[A receiver] resuming from offset {offset}", flush=True)
                    with partial_path.open("rb") as pf:
                        remaining = offset
                        while remaining > 0:
                            block = pf.read(min(CHUNK_SIZE, remaining))
                            if not block:
                                raise ValueError("partial file shorter than recorded offset")
                            h.update(block)
                            remaining -= len(block)
                    if h.hexdigest() != stored_prefix:
                        _quarantine(partial_path, ".bad-prefix-")
                        meta_p.unlink(missing_ok=True)
                        raise ValueError("partial file failed prefix hash check — stale data quarantined")
                else:
                    print("[A receiver] resuming from offset 0 (empty partial)", flush=True)
                send_all(tls_sock, MSG_RESUME + struct.pack(">Q", offset))
            else:
                send_all(tls_sock, MSG_GO + struct.pack(">Q", 0))
                partial_path.unlink(missing_ok=True)
                meta_p.unlink(missing_ok=True)
                offset = 0
                h = hashlib.sha256()
        else:
            send_all(tls_sock, MSG_GO + struct.pack(">Q", 0))
            partial_path.unlink(missing_ok=True)
            meta_p.unlink(missing_ok=True)

        with partial_path.open("r+b" if offset else "wb") as outf:
            if offset:
                outf.seek(offset)
            received = offset
            while received < total_size:
                tag = read_exact(tls_sock, len(MSG_CHNK))
                if tag != MSG_CHNK:
                    raise ValueError("expected CHNK")
                chunk_len = struct.unpack(">I", read_exact(tls_sock, 4))[0]
                if chunk_len == 0 or chunk_len > CHUNK_SIZE:
                    raise ValueError("illegal chunk size")
                data = read_exact(tls_sock, chunk_len)
                h.update(data)
                outf.write(data)
                received += chunk_len
                outf.flush()
                os.fsync(outf.fileno())
                meta_p.write_text(
                    json.dumps(
                        {
                            "file_id": file_id.hex(),
                            "chunk_size": CHUNK_SIZE,
                            "expected_size": total_size,
                            "expected_sha256": expected_digest.hex(),
                            "bytes_written": received,
                            "prefix_sha256": h.hexdigest(),
                        }
                    ),
                    encoding="utf-8",
                )

        done = read_exact(tls_sock, len(MSG_DONE))
        if done != MSG_DONE:
            raise ValueError("expected DONE")

        if received != total_size:
            raise ValueError("size mismatch after transfer")

        digest = h.digest()
        if digest != expected_digest:
            _quarantine(partial_path, ".sha256-fail-")
            meta_p.unlink(missing_ok=True)
            raise ValueError("SHA-256 mismatch - rejecting output")

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

        print("[A receiver] OK - file verified and installed", flush=True)
        exit_code = 0
        return exit_code
    except Exception as e:
        print(f"[A receiver] error: {e}", file=sys.stderr, flush=True)
        try:
            args.output.unlink(missing_ok=True)
        except OSError:
            pass
        if _is_likely_disconnect(e):
            print("[A receiver] connection lost — partial kept for resume if checkpoints are valid", flush=True)
        else:
            partial_path.unlink(missing_ok=True)
            meta_p.unlink(missing_ok=True)
        exit_code = 1
        return exit_code
    finally:
        if tls_sock is not None:
            try:
                tls_sock.close()
            except OSError:
                pass
        elif raw is not None:
            try:
                raw.close()
            except OSError:
                pass
        try:
            listener.close()
        except OSError:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
