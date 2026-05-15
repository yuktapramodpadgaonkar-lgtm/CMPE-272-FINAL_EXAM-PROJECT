# CMPE 272 — Secure 4 GB File Transfer (Two Approaches)

This repository implements two **architecturally different** end-to-end secure bulk file transfers over hostile TCP/IP, as required by the Security Engineering assessment. Both use **Python 3.11+**, **TCP**, **streaming chunk I/O** (1 MiB chunks), **SHA-256 over the full plaintext**, and **mutual authentication**.

| Directory | Idea | Highlights |
|-----------|------|------------|
| `approach-a-tls-mtls/` | **Transport-layer security** | Mutual TLS 1.2+ (RSA certs, `ssl` module). Confidentiality + record integrity from TLS **AEAD** (cipher suite negotiated by OpenSSL). Signed **`FHDR002`** manifest binds expected SHA-256 to sender identity; plaintext chunks inside TLS; end-to-end **SHA-256** of file. |
| `approach-b-app-aead/` | **Application-layer envelope** | Plain TCP + **ephemeral X25519** ECDH per session, **RSA-PSS** signed handshake transcripts, **ChaCha20-Poly1305** (`cryptography`) per chunk with explicit nonces and AAD. |

- **`DESIGN.md`** (repo root) — per-assessment **item 11**: architecture (ASCII), key management, framing, algorithms/parameters, and **row-by-row threat model** for each approach.
- **`AI_NOTES.md`** — required AI reflection (fill in run evidence before submit).

---

## How to install (fresh clone)

From the **repository root** (`CMPE-272-Final-Exam-Project/`):

**Windows (PowerShell)**

```powershell
cd CMPE-272-Final-Exam-Project
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python scripts\gen_certs.py
```

**Linux / macOS**

```bash
cd CMPE-272-Final-Exam-Project
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python scripts/gen_certs.py
```

Confirm PEM material exists under `certs/` (`ca.pem`, `receiver.pem`, `receiver-key.pem`, `sender.pem`, `sender-key.pem`). Generated `*.pem` / `*.key` are gitignored; run `gen_certs.py` on every fresh clone.

---

## How to generate the 4 GB test file (do not commit)

**Windows (zeros — fast, low entropy)**

```powershell
python -c "open('test_4gb.bin','wb').write(b'\x00'*(4*1024*1024*1024))"
```

**Linux / macOS (random)**

```bash
dd if=/dev/urandom of=test_4gb.bin bs=1M count=4096 iflag=fullblock
```

**Cross-platform (zeros; same as Windows one-liner)**

```bash
python -c "open('test_4gb.bin','wb').write(b'\x00'*(4*1024*1024*1024))"
```

Confirm size **4,294,967,296** bytes (e.g. `(Get-Item test_4gb.bin).Length` on Windows). The file is listed in `.gitignore` — **do not commit** it.

---

## Exact commands — run each approach end-to-end

Run from **repo root** with the **venv activated** and **`test_4gb.bin`** present. Use **two terminals** per approach.

### Approach A — mutual TLS (`approach-a-tls-mtls/`) — port **5000**

**Terminal 1 — receiver**

```powershell
python approach-a-tls-mtls\receiver.py --port 5000 --output received_a.bin
```

**Terminal 2 — sender**

```powershell
python approach-a-tls-mtls\sender.py --port 5000 --file test_4gb.bin --server-name 127.0.0.1
```

### Approach B — plain TCP + app AEAD (`approach-b-app-aead/`) — port **5001**

**Terminal 1 — receiver**

```powershell
python approach-b-app-aead\receiver.py --port 5001 --output received_b.bin
```

**Terminal 2 — sender**

```powershell
python approach-b-app-aead\sender.py --port 5001 --file test_4gb.bin
```

### Optional — independent SHA-256 compare (source vs received)

After a successful transfer:

```powershell
python scripts\verify_hashes.py test_4gb.bin received_a.bin
python scripts\verify_hashes.py test_4gb.bin received_b.bin
```

Streaming hash only (large files, low RAM):

```powershell
python scripts\sha256_stream.py test_4gb.bin
python scripts\sha256_stream.py received_a.bin
```

---

## Chunk size

Both implementations use **`CHUNK_SIZE = 1 MiB`** (`1024 * 1024` bytes).

---

## Repo layout

```
approach-a-tls-mtls/   sender.py, receiver.py, manifest_crypto.py
approach-b-app-aead/   sender.py, receiver.py, _proto.py
scripts/               gen_certs.py, sha256_stream.py, verify_hashes.py
certs/                 generated PEMs (gitignored except certs/README.md)
DESIGN.md              item 11 — design + threat model (both approaches)
documentation/       extra runbooks and AI prompt log (optional)
```

---

## Quick rubric checks

- **Wrong cert / key:** use `--certs-dir` pointing at a folder with a mismatched `sender-key.pem` on the sender; TLS or handshake should fail before a valid file is installed.
- **Mid-transfer drop:** stop the sender; restart receiver then sender with the same `--output` — resume when `.partial` + `.meta.json` match (details in `DESIGN.md`).

---

## Academic integrity

Follow your course policy. Run a **real 4 GB** transfer yourself and record hashes and dates in `AI_NOTES.md` before submission.
