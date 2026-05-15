# Secure 4 GB Transfer — Design (Both Approaches)

This document satisfies the assessment requirement for architecture, algorithms, and an explicit **CIAA** mapping with a **row-per-threat** table for each approach.

---

## Shared constants (both approaches)

| Item | Value | Rationale |
|------|-------|-----------|
| Chunk size | **1 MiB** (`1_048_576` bytes) | Keeps memory bounded while amortizing syscalls on Windows. |
| Whole-file integrity | **SHA-256** over **plaintext** | Independent of transport AEAD; detects truncation/reordering bugs at the file layer. |
| Mutual authentication | **RSA 2048** X.509 certs issued by a local demo **CA** (`scripts/gen_certs.py`) | Not a production PKI; demonstrates trust anchors and fail-closed verification. |
| Fail-closed storage | Receiver writes **`*.partial`** + **`*.meta.json`**, verifies, then **rename** | Prevents a half-finished file from masquerading as the final object. |

---

## Approach A — mutually authenticated TLS (transport security)

### ASCII architecture

```
Sender (TLS client + sender.pem)                Receiver (TLS server + receiver.pem)
        |                                                    |
        |=========== TCP + TLS 1.2+ (AEAD records) =========>|
        |   (ECDHE key exchange if negotiated; FS optional)  |
        |                                                    |
        |--- APP: MAGIC, FHDR002(signed manifest: size, sha256, nonce) -->|
        |<-- APP: READY(nonce), GO/RESUME(offset) ----------|
        |--- APP: CHNK*(plaintext) -------------------------->|
        |--- APP: DONE ------------------------------------->|
        |                                                    | verify SHA-256
        |                                                    | rename -> final path
```

### Key exchange / trust

1. **Trust anchor:** each side loads `certs/ca.pem`.
2. **Server identity:** receiver presents `receiver.pem` (CN `file-transfer-receiver`, SAN `localhost` + `127.0.0.1`).
3. **Client identity:** sender presents `sender.pem` (CN `file-transfer-sender`, EKU **clientAuth**).
4. **Python `ssl`:** `CERT_REQUIRED` on both ends; **no** `check_hostname=False` shortcuts.
5. **Session binding:** receiver sends random `server_nonce`; sender echoes it inside the signed manifest so an old manifest cannot be replayed against a fresh session without breaking TLS.
6. **Manifest signature:** after mTLS, the sender sends `FHDR002` = `file_id` (16 B, `SHA256(digest||size)[:16]`) + size + SHA-256 digest + echoed nonce + **RSA-PSS-SHA256** signature over those bytes using **`sender-key.pem`**. The receiver verifies with the **client certificate public key** from `getpeercert(binary_form=True)`, binding the claimed file hash to the authenticated sender identity (not only TLS record protection).

### Chunking / framing (inside TLS)

| Frame | Bytes | Meaning |
|-------|-------|---------|
| `SECFTA1` | 7 | Magic |
| `READY01` + 16 | 7+16 | Receiver random |
| `FHDR002` + 16 `file_id` + u64 BE size + 32 digest + 16 echo + u32 siglen + RSA-PSS sig | | Signed file manifest (inside TLS) |
| `GO00001`+u64 or `RESUM01`+u64 | | Start offset |
| `CHNK001` + u32 BE len + plaintext | | Chunk |
| `DONE001` | 7 | Sender finished sending declared size |

### Algorithms (explicit)

| Layer | Algorithm / mechanism | Parameters |
|-------|----------------------|------------|
| Transport | TLS 1.2+ with OpenSSL-backed AEAD suites (e.g., AES-GCM) | Negotiated; **minimum** TLS 1.2 |
| Certificates | RSA 2048, SHA-256 signature on CSR | 2048-bit, SHA-256 |
| File integrity | SHA-256 | 256-bit digest over plaintext stream |

### CIAA mapping — Approach A

| Property | Mechanism in this code |
|----------|------------------------|
| **C — Confidentiality** | TLS record encryption (AEAD). File bytes never leave the sender process in cleartext on the wire. |
| **I — Integrity** | TLS record authentication **plus** independent SHA-256 over plaintext at receiver; `DONE` + size check. |
| **A — Authenticity** | Mutual TLS: both parties present certs signed by the configured CA; wrong cert aborts handshake. |
| **A — Availability** | TCP retransmissions; chunked I/O; **resume** using signed offsets is approximated via authenticated channel metadata (`RESUM01` + offset) with `.meta.json` checkpoints after `fsync`. |

### Threat model table — Approach A

| Threat | CIAA | How this design answers it (and where in code) |
|--------|------|---------------------------------------------------|
| Passive eavesdropper | C | TLS ciphertext; attacker learns timing/volume only. |
| Active MITM modifies bytes | I | TLS AEAD rejects record tampering; even if broken, **SHA-256** over plaintext fails at finalize. |
| Spoof sender/receiver | A | mTLS: peer cert must chain to `ca.pem` with expected CN. |
| Replay of earlier transfer | I / A | Fresh TLS session + fresh `server_nonce` in signed manifest binds metadata to this session. |
| Connection drop at 80% | A | Partial file not renamed; metadata tracks bytes; **resume** continues hashing by re-reading partial prefix then appending. |
| Untrusted broker | n/a | Not used in Approach A. |

---

## Approach B — application-layer AEAD on plain TCP

### ASCII architecture

```
Sender                                    Receiver
  | plain TCP                                |
  |---- u32-len: ClientHandshake ----------->|
  |<--- u32-len: ServerHandshake ------------|
  |      (RSA-PSS signatures bind ephemera + randoms)        |
  |                                            |
  |== X25519 ECDH => HKDF-SHA256 keys ========|
  |                                            |
  |---- AEAD(meta) --------------------------->|
  |<--- AEAD(GO|RS + offset) -------------------|
  |---- AEAD(chunk_i) ----------------------->|
  |                                            | verify tags + SHA-256
```

### Key exchange / trust

1. Each side loads long-term **RSA** cert + key (`sender.pem` / `receiver.pem`) trusted via `ca.pem`.
2. **Ephemeral X25519** keys per session (`X25519PrivateKey.generate()`).
3. **RSA-PSS-SHA256** signatures cover transcript bytes that include both random nonces and ephemeral public keys — mutual authentication without TLS.
4. **HKDF-SHA256** (`cryptography` HKDF) derives separate symmetric keys for **control/meta** (`info=b"meta"`) and **payload** (`info=b"payload"`).
5. **Session binding digest** `SHA256(client_random||server_random)[:16]` is included inside AEAD-protected metadata so a metadata blob cannot be cut-and-pasted across sessions.

### Chunking / framing

- All payloads after the handshake are **`u32_be_length || bytes`**.
- **Metadata** (nonce index `1`, key `k_meta`): `size_u64_be || sha256 || bind16` with AAD `META/1`.
- **Control** (nonce index `2`): `GO` + `0` offset or `RS` + `u64` offset with AAD `SCTRL/1`.
- **Data chunks** (nonce index `3 + seq`): ciphertext with AAD `DATA/1 || u64_current_offset || u64_total_size` to cryptographically bind each chunk to its logical position and file length (**reorder / truncate detection**).

### Algorithms (explicit)

| Purpose | Algorithm | Parameters |
|---------|-----------|------------|
| Key agreement | **X25519** ECDH | 32-byte public keys (`Encoding.Raw`) |
| KDF | **HKDF-SHA256** | 32-byte keys, `salt=b"cmpe272-approach-b"` |
| AEAD | **ChaCha20-Poly1305** | 256-bit keys, **96-bit nonce** = `index.to_bytes(12,"big")` (monotonic per session) |
| Handshake auth | **RSA-PSS** with **MGF1-SHA256** | MAX salt length |
| Whole-file integrity | **SHA-256** over plaintext | Same as Approach A |

### Forward secrecy (explicit note)

If a **long-term RSA private key** is compromised later, an attacker could forge future handshakes, but **past session X25519 ephemera** are not recoverable from those long-term keys alone. Therefore **past ciphertext confidentiality** enjoys a form of **forward secrecy** with respect to the signing keys, provided ephemeral private keys are zeroed after use (Python GC does not guarantee immediate erasure; production code would zeroize).

### CIAA mapping — Approach B

| Property | Mechanism |
|----------|-----------|
| **C** | ChaCha20-Poly1305 on every metadata/chunk; keys from fresh ECDH. |
| **I** | AEAD tags per frame; AAD binds offset+total; SHA-256 over plaintext end-to-end. |
| **A** | RSA certs verified to CA + RSA-PSS signatures over handshake transcripts. |
| **A** | Same as Approach A: TCP + chunking + resume metadata + `fsync` checkpoints. |

### Threat model table — Approach B

| Threat | CIAA | How this design answers it |
|--------|------|------------------------------|
| Passive eavesdropper | C | Only ciphertext + ciphertext lengths on the wire; keys from ECDH. |
| Active MITM modifies bytes | I | Poly1305 tag verification fails; chunk rejected. |
| Spoof sender/receiver | A | Signature verification fails if attacker lacks private key matching enrolled cert. |
| Replay of earlier transfer | I / A | New ECDH + new HKDF keys + binding digest in metadata. |
| Connection drop at 80% | A | Same partial-file discipline as Approach A. |
| Untrusted broker | n/a | Not implemented here; **Approach B is architecturally suitable** to stack atop dumb object storage because plaintext never touches the store if you encrypt client-side with per-object keys (out of scope for this repo). |

---

## Broker / storage extension (design note only)

To add a **malicious cloud bucket** while keeping CIAA:

1. Sender **encrypts** with AEAD (as in Approach B) **before** upload; uploads only `(nonce, ciphertext, AAD metadata)` plus a **signed manifest** (Ed25519 or RSA-PSS) listing chunk hashes/order.
2. Receiver downloads, verifies manifest signature against sender cert, verifies each chunk AEAD, verifies whole-file SHA-256.
3. The broker learns **ciphertext + traffic patterns** only.

This demonstrates **defense against an untrusted intermediary** without trusting it for plaintext.
