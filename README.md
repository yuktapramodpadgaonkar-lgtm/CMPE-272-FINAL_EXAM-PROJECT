# CMPE 272 — Secure 4 GB File Transfer (Two Approaches)

This repository implements two **architecturally different** end-to-end secure bulk file transfers over hostile TCP/IP, as required by the Security Engineering assessment. Both use **Python 3.11+**, **TCP**, **streaming chunk I/O** (1 MiB chunks), **SHA-256 over the full plaintext**, and **mutual authentication**.

| Directory | Idea | Highlights |
|-----------|------|------------|
| `approach-a-tls-mtls/` | **Transport-layer security** | Mutual TLS 1.2+ (RSA certs, `ssl` module). Confidentiality + record integrity from TLS **AEAD** (cipher suite negotiated by OpenSSL). Application frames carry plaintext chunks; an independent **end-to-end SHA-256** commits the file. |
| `approach-b-app-aead/` | **Application-layer envelope** | Plain TCP + **ephemeral X25519** ECDH per session, **RSA-PSS** signed handshake transcripts, **ChaCha20-Poly1305** (`cryptography`) per chunk with explicit nonces and AAD. |

See `DESIGN.md` for CIAA mapping, algorithms, and threat-model tables. See `AI_NOTES.md` for the required AI collaboration reflection (edit with your own session specifics before submitting).

## Prerequisites

- Python 3.11 or newer on your PATH as `python`.
- ~5 GB free disk space to **generate** the test file (the file itself is gitignored).

## Install (fresh clone)

```powershell
cd CMPE-272-Final-Exam-Project
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python scripts\gen_certs.py
```

This writes PEM files under `certs/` (ignored by git except `certs/README.md`).

## Generate the 4 GB test file (do not commit)

**Windows PowerShell (zeros, fast):**

```powershell
python -c "open('test_4gb.bin','wb').write(b'\x00'*(4*1024*1024*1024))"
```

**Linux / macOS random data:**

```bash
dd if=/dev/urandom of=test_4gb.bin bs=1M count=4096 iflag=fullblock
```

## Hash the file (verify on both ends)

**Python (any OS):**

```powershell
python -c "import hashlib, pathlib; print(hashlib.sha256(pathlib.Path('test_4gb.bin').read_bytes()).hexdigest())"
```

(Streaming variant for huge files: run `python scripts\sha256_stream.py test_4gb.bin`.)

**Windows built-in:**

```powershell
certutil -hashfile test_4gb.bin SHA256
```

## Approach A — mutual TLS (`approach-a-tls-mtls`)

Default port **5000**. Receiver binds; sender connects as TLS **client** with **client certificate**.

**Terminal 1 — receiver**

```powershell
.\.venv\Scripts\python approach-a-tls-mtls\receiver.py --port 5000 --output received_a.bin
```

**Terminal 2 — sender**

```powershell
.\.venv\Scripts\python approach-a-tls-mtls\sender.py --port 5000 --file test_4gb.bin --server-name 127.0.0.1
```

The receiver writes to `received_a.bin.partial` while copying, updates `*.meta.json` for resumability, verifies **SHA-256 == sender header**, then atomically installs `received_a.bin`.

### Quick tamper / wrong-cert checks

- **Wrong client key:** temporarily point `--certs-dir` at a copy of `certs` where `sender-key.pem` is replaced; the TLS handshake should fail before any file bytes are accepted.
- **Kill mid-transfer:** stop the sender process; rerun the receiver then sender — if the partial metadata matches, the transfer **resumes** from the last fsynced offset.

## Approach B — app-layer AEAD (`approach-b-app-aead`)

Default port **5001** (so you can run A and B receivers side by side).

**Terminal 1 — receiver**

```powershell
.\.venv\Scripts\python approach-b-app-aead\receiver.py --port 5001 --output received_b.bin
```

**Terminal 2 — sender**

```powershell
.\.venv\Scripts\python approach-b-app-aead\sender.py --port 5001 --file test_4gb.bin
```

## Chunk size

Both implementations use **`CHUNK_SIZE = 1 MiB`** (`1024 * 1024` bytes). This limits resident memory while keeping syscall overhead reasonable on Windows.

## Repo layout

```
approach-a-tls-mtls/   sender.py, receiver.py
approach-b-app-aead/   sender.py, receiver.py, _proto.py
scripts/               gen_certs.py, sha256_stream.py
certs/                 generated PEM material (gitignored)
DESIGN.md              architecture + threat model
AI_NOTES.md            AI collaboration reflection (fill in)
```

## Academic integrity

Follow your course policy. This scaffold is meant to be read, understood, and exercised (including the real 4 GB run) before submission.
