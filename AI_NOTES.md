# AI Collaboration Notes (Required Reflection)

A structured **prompt → answer → conclusion** log from this project’s working chat (including alternative architectures you could have chosen) lives in:

**`documentation/AI_NOTES_MY_PROMPTS_AND_DOUBTS.md`**

> **Instructions:** Keep this honest and specific. Replace bracketed prompts with your own experience after you run, test, and edit the code.

## Tools used

- Primary: **Claude** (Cursor) for scaffolding, protocol framing, and doc structure.
- (Optional) list any other assistants or linters here: `[ ... ]`

## What the AI produced end-to-end

- **Approach A (`approach-a-tls-mtls/`)**: `[ describe which files or sections were mostly AI-generated vs hand-edited ]`
- **Approach B (`approach-b-app-aead/`)**: `[ same ]`
- **Docs (`README.md`, `DESIGN.md`)**: `[ same ]`

## One concrete insecure or incorrect proposal — and how you caught it

During certificate generation scaffolding, the initial CA `KeyUsage` extension omitted the `key_encipherment` keyword entirely. On Windows with **cryptography 46+**, `x509.KeyUsage(...)` raised a `TypeError` at import time, which surfaced immediately when running `scripts/gen_certs.py`.

The fix was to pass **all** `KeyUsage` fields explicitly (setting unused usages to `False`), matching the library’s required constructor shape.

> Replace this paragraph if your own chat log contains a *security-relevant* pushback (for example rejecting `check_hostname=False`, rejecting CBC without MAC, or rejecting nonce reuse).

## One thing the model did better than expected

`[ e.g., catching a framing bug, suggesting HKDF labels, structuring the threat table ]`

## One thing the model did worse than expected

`[ e.g., over-engineering, subtle Windows path issues, missing socket timeouts ]`

## Architectural decisions you owned (not the AI)

1. **Pairing of approaches:** Transport-layer **mTLS** (A) vs **application-layer AEAD** on plain TCP (B) — different trust boundaries and attack surfaces.
2. **Chunk size:** 1 MiB — balances Windows I/O and memory.
3. **Resume strategy:** Authenticated control plane + on-disk `.partial` + `.meta.json` + `fsync` before advertising progress.

## Evidence you actually ran the code

- Date/time of your local **4 GB** transfer for Approach A: `[ ... ]`
- Date/time for Approach B: `[ ... ]`
- SHA-256 of `test_4gb.bin` (both ends matched): `[ paste hash ]`

## If you diverged from this scaffold

Document any changes here so graders can follow the diff.
