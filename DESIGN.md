# Secure 4 GB Transfer — Design (Both Approaches)

This file is the **single repo-root `DESIGN.md`** required by the assessment (**item 11**). It covers **both** approaches: ASCII architecture, key exchange / key management, chunking and framing, **exact algorithms and parameters**, and a **row-by-row threat model** aligned with the course threat table.

---

## Shared constants (both approaches)

| Item | Value | Rationale |
|------|-------|-----------|
| Chunk size | **1 MiB** (`1_048_576` bytes) | Bounded memory; reasonable syscall rate on Windows. |
| Whole-file integrity | **SHA-256** over **plaintext** | End-to-end commitment independent of per-chunk / per-record crypto. |
| Identity / trust anchor | **RSA 2048-bit** X.509 certs, **SHA-256** cert signatures, demo **CA** (`scripts/gen_certs.py`) | Demonstrates mutual trust without building a PKI. |
| Fail-closed storage | **`*.partial`** + **`*.meta.json`**, `fsync`, then **atomic install** to final path | No half file presented as complete. |

---

# Approach A — Mutually authenticated TLS (transport-layer security)

## ASCII architecture diagram

```
  Sender (TLS client, sender.pem)                    Receiver (TLS server, receiver.pem)
           |                                                    |
           |==== TCP + TLS 1.2+ (ECDHE optional; AEAD records) ==|
           |                                                    |
           |--- APP: SECFTA1 ---------------------------------->|
           |<-- APP: READY01 || server_nonce (16 B) ------------|
           |--- APP: FHDR002 || signed manifest ---------------->|
           |       (file_id, size, SHA-256, echo nonce, RSA-PSS)|
           |<-- APP: GO00001||u64 OR RESUM01||u64 offset --------|
           |--- APP: CHNK001||u32 len|| plaintext -------------->|
           |        ... repeat while bytes < total_size ...      |
           |--- APP: DONE001 ----------------------------------->|
           |                                                    |
           |                              stream hash(plaintext)|
           |                              if size+SHA-256 OK:  |
           |                              partial -> temp ->  |
           |                              rename received file  |
```

## Key exchange / key management

| Step | Mechanism |
|------|-----------|
| Long-term keys | **RSA 2048** key pairs in `sender-key.pem`, `receiver-key.pem`; certs signed by **CA** (`ca.pem`). |
| Transport keys | **TLS 1.2+** handshake; typically **ECDHE** ephemeral key exchange (if negotiated by stack) for session keys; **AEAD** for application data records (suite negotiated by OpenSSL / platform). |
| Trust | Server presents `receiver.pem`; client presents `sender.pem`; **`ssl.CERT_REQUIRED`**; client **`check_hostname=True`** against SAN (`localhost`, `127.0.0.1`). |
| File commitment | After TLS is live, **`FHDR002`**: 16-byte **`file_id = SHA256(digest \|\| BE64(size))[:16]`**, **64-bit BE file size**, **32-byte SHA-256 digest**, **16-byte echoed `server_nonce`**, **RSA-PSS-SHA256** signature over `file_id \|\| size \|\| digest \|\| echo` using **`sender-key.pem`**. Receiver verifies signature with **mTLS client public key** from `SSLSocket.get_peercert(binary_form=True)`. |

## Chunking and framing (application bytes, inside TLS ciphertext on the wire)

| On-the-wire sequence (plaintext view inside TLS) | Format |
|---------------------------------------------------|--------|
| Magic | `SECFTA1` (7 bytes) |
| Ready | `READY01` (7) + `server_nonce` (16) |
| Signed manifest | `FHDR002` (7) + `file_id` (16) + `size` (u64 BE) + `sha256_digest` (32) + `echo_nonce` (16) + `sig_len` (u32 BE) + **RSA-PSS-SHA256** signature |
| Control | `GO00001` (7) + u64 BE (0 for fresh) **or** `RESUM01` (7) + u64 BE **resume offset** |
| Data | Repeated: `CHNK001` (7) + u32 BE **chunk length** + **plaintext** (≤ 1 MiB) |
| End | `DONE001` (7) |

Receiver updates **`SHA256(plaintext stream)`** incrementally; after `DONE`, requires **`received_bytes == size`** and **`digest == expected_digest`**.

## Exact algorithms and parameters — Approach A

| Role | Algorithm / primitive | Parameters / notes |
|------|------------------------|-------------------|
| Transport protocol | **TLS** | **Minimum TLS 1.2** (`ssl.TLSVersion.TLSv1_2`); `PROTOCOL_TLS_CLIENT` / `PROTOCOL_TLS_SERVER`. |
| Record protection | **TLS negotiated AEAD** (e.g. **AES-256-GCM** or ChaCha20-Poly1305 with typical modern stacks) | Not hard-coded in Python; chosen by OpenSSL/platform from enabled cipher suites. |
| Certificate keys | **RSA 2048**, cert signed with **SHA-256** | `gen_certs.py`: public exponent **65537**. |
| Certificate chain validation | **X.509**: issuer subject match + **RSASSA-PKCS1-v1_5** signature verification on `tbs_certificate_bytes` | Demo CA verifies child certs (`cryptography` patterns where applicable). |
| Manifest signature | **RSA-PSS** with **MGF1-SHA256**, **SHA-256** message hash, **PSS MAX_LENGTH** salt | Signs the **56-byte** manifest prefix (`file_id` + size + digest + echo nonce). |
| File integrity | **SHA-256** | **256-bit** digest over **entire plaintext file**; compared after transfer. |

## CIAA — Approach A (summary)

| Property | Mechanism |
|----------|-----------|
| **C — Confidentiality** | TLS encrypts application data on the wire. |
| **I — Integrity** | TLS **AEAD** on records + **SHA-256** over full plaintext + size/`DONE` discipline. |
| **A — Authenticity** | **Mutual TLS** + **RSA-PSS** on manifest binding digest to **authenticated client key**. |
| **A — Availability** | **TCP** retransmits; **chunked** send/recv; **resume** via `.partial` + `.meta.json` (including **`prefix_sha256`** checkpoint in Approach A code); disconnect preserves partial for retry. |

## Threat model table — Approach A (row-by-row)

Rows match the **course threat model**; each row states how Approach A addresses it.

| Threat (as in assignment) | CIAA bucket | How Approach A satisfies “what you must show” |
|----------------------------|-------------|-----------------------------------------------|
| **Passive eavesdropper** records the entire TCP stream. | **Confidentiality** | File bytes cross the network as **TLS ciphertext**; ephemeral session keys are negotiated inside TLS; long-term **RSA private keys** are not sent on the wire. |
| **Active man-in-the-middle** modifies bytes mid-flight. | **Integrity** | **TLS AEAD** rejects altered ciphertext for affected records; receiver **rejects** the transfer if the **end-to-end SHA-256** over plaintext does not match the **signed manifest** digest. |
| **Attacker spoofs** the sender or the receiver. | **Authenticity** | **mTLS**: handshake fails without valid cert chain to **`ca.pem`** and expected **CN**; manifest signature fails without **`sender-key.pem`** matching the presented client cert. |
| **Replay** of an earlier valid transfer. | **Integrity / Authenticity** | Each session uses a new **TLS** context and new **`server_nonce`** echoed inside the **signed manifest**; replaying an old manifest blob against a new session fails **nonce binding** and/or **TLS** session keys. |
| **Connection drops** at 80% transferred. | **Availability** | Receiver does **not** rename to the final path until **size + SHA-256** succeed; **partial file + JSON metadata** allow **resume** when the client reconnects with the same file identity. |
| **Untrusted intermediary** (broker / object store), if used. | **Confidentiality / Integrity** | **Not used** in this implementation. A broker would only ever see **TLS ciphertext** if traffic were relayed; plaintext would still not be entrusted to the broker by this design. |

---

# Approach B — Application-layer AEAD on plain TCP

## ASCII architecture diagram

```
  Sender                                              Receiver
    |---- TCP connect --------------------------------->|
    |---- u32 BE len || ClientHandshake blob --------->|
    |<--- u32 BE len || ServerHandshake blob ----------|
    |      (RSA-PSS over transcript incl. randoms + X25519 pub keys)   |
    |                                                    |
    |    ECDH: X25519(client_ephem) <-> X25519(server_ephem)          |
    |    HKDF-SHA256 -> k_meta (32 B), k_payload (32 B)                 |
    |                                                    |
    |---- u32 BE len || AEAD_chacha(k_meta, nonce=1, meta) ----------->|
    |<--- u32 BE len || AEAD_chacha(k_meta, nonce=2, GO|RS||offset) --|
    |---- u32 BE len || AEAD_chacha(k_payload, nonce=3+i, chunk_i) --->|
    |        ... until all plaintext bytes sent ...                    |
    |                                                    | SHA-256 OK? |
    |                                                    | rename out |
```

## Key exchange / key management

| Step | Mechanism |
|------|-----------|
| Long-term keys | Same **RSA 2048** PEM certs as Approach A (`sender`, `receiver`), verified against **`ca.pem`**. |
| Ephemeral keys | Per connection: **`X25519PrivateKey.generate()`** on each side; 32-byte **raw** public keys in handshake blobs. |
| Shared secret | **`X25519.exchange()`** → 32-byte shared bytes. |
| Key derivation | **HKDF-SHA256**, `salt=b"cmpe272-approach-b"`, **`info=b"meta"`** → 32 B **`k_meta`**; **`info=b"payload"`** → 32 B **`k_file`**. |
| Handshake integrity / auth | **RSA-PSS-SHA256** (MGF1-SHA256, MAX salt) over defined byte strings including **client_random**, **server_random**, and **ephemeral public keys**. |
| Metadata binding | **`SHA256(client_random \|\| server_random)[:16]`** inside AEAD plaintext so metadata cannot be replayed across sessions. |

## Chunking and framing

| Phase | Framing |
|-------|---------|
| Handshake | **`u32 big-endian length`**, then **blob** (magic, version, randoms, cert PEM, signature …). |
| Metadata | **`u32 BE length`**, then **ChaCha20-Poly1305** ciphertext; **nonce** = `nonce_for_index(1)`; **AAD** = `META/1`; plaintext = **`u64 BE size` \|\| 32 B digest \|\| 16 B bind`**. |
| Resume control | **`u32 BE length`**, AEAD with **nonce 2**, **AAD** `SCTRL/1`; plaintext **`GO` + u64** or **`RS` + u64 offset**. |
| File chunks | **`u32 BE length`**, AEAD with **nonce `3 + seq`** (monotonic **96-bit** big-endian integer); **AAD** = `DATA/1` \|\| **`u64 BE byte offset`** \|\| **`u64 BE total_size`**; plaintext = up to **1 MiB** file slice. |

## Exact algorithms and parameters — Approach B

| Role | Algorithm / primitive | Parameters / notes |
|------|------------------------|-------------------|
| Key agreement | **X25519** (RFC 7748) | 32-byte **encoded** public keys (`Encoding.Raw`). |
| KDF | **HKDF-SHA256** | Output **32 bytes** per label; **salt** fixed string `cmpe272-approach-b`. |
| Symmetric AEAD | **ChaCha20-Poly1305** | **256-bit** keys; **96-bit nonce** = `index.to_bytes(12, "big")`; unique **index** per AEAD operation in a session. |
| Handshake signatures | **RSA-PSS-SHA256**, **MGF1-SHA256**, **PSS MAX_LENGTH** salt | Same RSA **2048-bit** keys as certs. |
| Certificate validation | **X.509** child-to-CA | Issuer match + **PKCS#1 v1.5** signature verification on **`tbs_certificate_bytes`** with CA public key (`cryptography`). |
| File integrity | **SHA-256** | **256-bit** digest over **entire decrypted plaintext** stream. |

## CIAA — Approach B (summary)

| Property | Mechanism |
|----------|-----------|
| **C** | **ChaCha20-Poly1305** on metadata and chunks; keys from **fresh ECDH** each session. |
| **I** | **Poly1305** tags + **AAD** binds chunk offset and total size; **SHA-256** over full plaintext. |
| **A** | **RSA-PSS** handshake signatures + **X.509** mutual identification to **CA**. |
| **A** | **TCP** + chunked I/O + **partial + meta** resume (metadata fields as implemented in `approach-b-app-aead/receiver.py`). |

## Threat model table — Approach B (row-by-row)

| Threat (as in assignment) | CIAA bucket | How Approach B satisfies “what you must show” |
|----------------------------|-------------|-----------------------------------------------|
| **Passive eavesdropper** records the entire TCP stream. | **Confidentiality** | File appears as **ChaCha20-Poly1305 ciphertext** and handshake components that do not disclose long-term private keys; **session keys** derive from **X25519** shared secret. |
| **Active man-in-the-middle** modifies bytes mid-flight. | **Integrity** | **AEAD decrypt** fails (bad tag) for tampered ciphertext; wrong plaintext will fail final **SHA-256** vs metadata digest. |
| **Attacker spoofs** the sender or the receiver. | **Authenticity** | **RSA-PSS** verification fails without the correct **private key** matching the peer’s **cert**; **CA**-pinned chain rejects forged certs. |
| **Replay** of an earlier valid transfer. | **Integrity / Authenticity** | New **X25519** ephemera → new **HKDF** keys; **binding digest** in metadata ties ciphertext to this session’s randoms. |
| **Connection drops** at 80% transferred. | **Availability** | Receiver does not install final output until completion and **SHA-256** match; **partial + meta** support resuming when metadata still matches the new session’s announced digest/size. |
| **Untrusted intermediary** (broker / object store), if used. | **Confidentiality / Integrity** | **Not implemented** as a separate hop in this repo. The design **fits** “encrypt client-side, upload ciphertext + signed manifest only”: broker never receives **plaintext** or **long-term symmetric keys** if that pattern were added. |

---

## Broker extension (design note only — optional stretch)

1. AEAD-encrypt chunks **before** upload; store only ciphertext + per-chunk nonces + **signed manifest** (chunk order, total size, **SHA-256**).
2. Receiver verifies **manifest signature**, each **AEAD** tag, then **whole-file SHA-256**.
3. Broker compromise yields **ciphertext** and **traffic metadata** only, not plaintext.

---

## Document map (assessment alignment)

| Assessment reference | File |
|----------------------|------|
| **Item 10** — install, 4 GB generation, exact end-to-end commands | **`README.md`** (this repo’s root) |
| **Item 11** — architecture, keys, framing, algorithms, threat tables **per approach** | **`DESIGN.md`** (this file; both approaches) |
