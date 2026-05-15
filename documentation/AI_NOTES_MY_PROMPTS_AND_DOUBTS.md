# AI notes — my prompts, doubts, answers, and conclusions

This document records **topics raised in chat** (paraphrased as “you asked”), **how the assistant answered**, and a **one-line conclusion** you can reuse when writing the course `AI_NOTES.md`. Wording is reconstructed from the thread, not verbatim quotes.

---

## Prompt log (question → answer → conclusion)

| # | What you asked (summary) | What the assistant answered (summary) | Conclusion |
|---|---------------------------|----------------------------------------|------------|
| 1 | Build the full CMPE 272 secure 4 GB transfer project (two approaches, CIAA, docs, no secrets in code). | Scaffolded two implementations (Python), cert script, README/DESIGN/AI_NOTES template, step doc, streaming chunks, AEAD rules, resume/fail-safe behavior. | You still must run a **real 4 GB** transfer and personalize reflection fields. |
| 2 | Background shell tasks finished — what happened? | Approach A/B smoke receivers exited 0; transfers completed for small test files. | Background jobs were **successful**; not a substitute for your own 4 GB evidence. |
| 3 | Create a text file of **every step** to run the project, in another folder, filename tied to “documentation”. | Added `documentation/documentation-steps.txt` with numbered setup, 4 GB creation, both approaches, optional checks. | Use that file as your **personal runbook** during demo recording. |
| 4 | What does `scripts/gen_certs.py` do? What are TLS/signing certs for? What do they ensure? | Script builds a demo CA plus `receiver` (serverAuth) and `sender` (clientAuth) RSA certs; Approach A uses them for **mTLS**; Approach B uses them for **RSA-PSS transcript signing**; they anchor **authenticity** (who is speaking) when combined with private key protection. | Certs are **identity + trust anchor**, not the same thing as file encryption by themselves. |
| 5 | Explain **Approach A** in easy words and how it satisfies **CIAA**. | Plain-language map: TLS gives confidentiality/integrity on the wire + mutual auth; SHA-256 over plaintext gives end-to-end file commitment; TCP + chunking + partial/retry supports availability. | **Two layers**: TLS for the channel, SHA-256 for the **whole file** story. |
| 6 | Are we **reusing the same (key, nonce)** across chunks? | Approach A: app sends plaintext chunks; TLS stack manages record keys/nonces. Approach B: one `k_file` but **unique nonce per chunk** via `nonce_for_index(3 + seq)`. | Safe pattern is **one key, many nonces**; never same **(key, nonce)** for two different encryptions. |
| 7 | Is hashing checked **per chunk** or **after the entire file**? | SHA-256 is **updated every chunk** (streaming) but **compared once** at the end; Approach B AEAD (and TLS records in A) authenticate smaller units earlier. | Meets the brief: **AEAD early**, **whole-file hash** at the end. |
| 8 | **Where** is the sent file’s SHA-256? | Approach A: in `FHDR` payload over TLS (later upgraded to signed `FHDR002`); Approach B: inside encrypted metadata; resume JSON stores hex copy. | Hash is **in the opening manifest**, not a separate mystery file in git. |
| 9 | Can hash checking be **automated**? Is it already? | Receiver **already** verifies against sender-declared digest; added `scripts/verify_hashes.py` for an independent **source vs received** compare. | **Two levels**: protocol-enforced + optional third-party style check for demos. |
|10 | **Review Approach A** for: authenticated hash manifest, rich resume metadata, fail-closed rename rules, no silent reuse of corrupted partials. | TLS already covered wire; added **RSA-PSS signed manifest** (`FHDR002`), deterministic `file_id`, `chunk_size` in meta, `prefix_sha256` before resume, quarantine paths on failure, keep partials on **disconnect** only. | Earlier version leaned on TLS alone for manifest bytes; review tightened **authenticity binding** and **resume safety**. |

---

## Extra question (from you): all possible ways to do the project — why these two?

### Credible “families” of solution (TCP, CIAA-minded)

Below are **architecturally different** buckets the brief encourages. You only need **two**; the rest are alternatives you could have picked instead.

1. **Mutual TLS, stream the file inside the tunnel** (what **Approach A** is)  
   - Crypto mostly in the **TLS record layer** (negotiated AEAD).  
   - App may still add **end-to-end file hash** for an explicit file commitment.

2. **Plain TCP + application crypto** (what **Approach B** is)  
   - **ECDH** (or similar) for session keys, **AEAD per chunk** or per message, **cert-based or signed** handshake.  
   - TLS is **not** the bulk confidentiality mechanism.

3. **Encrypt-to-disk / envelope first, move ciphertext over dumb transport**  
   - Example: produce `file.enc` + manifest locally, then `scp`, HTTP PUT, or raw TCP of **ciphertext only**.  
   - Differs from (2) mainly in **lifecycle** (offline encrypt vs online streaming).

4. **Broker / object storage in the middle**  
   - Upload ciphertext + **signed chunk manifest**; broker never sees keys or plaintext.  
   - Strong story for “untrusted intermediary” stretch goal.

5. **Tunnel/VPN then naive copy**  
   - IPsec/WireGuard/OpenVPN: security is mostly **network layer**, not a custom file protocol — weaker match if graders want **explicit** chunking + app threat table.

6. **PSK-only (pre-shared symmetric key) + AEAD chunks**  
   - Meets crypto bar if documented; **less** “public Internet strangers” realism unless you explain key distribution.

7. **Noise / Signal-style handshakes**  
   - Excellent crypto design; more moving parts than needed for a timed exam unless you already know Noise.

8. **Out-of-scope per your brief**  
   - **UDP/QUIC** unless you justify; **home-grown ciphers** forbidden.

### Why **these two** were chosen here

| Criterion | Approach A (**mTLS**) | Approach B (**app AEAD + ECDH + signed handshake**) |
|-----------|------------------------|------------------------------------------------------|
| **Meaningful architectural contrast** | Security is **primarily transport-layer** (`ssl`, TLS AEAD, cert auth). | Security is **primarily application-layer** on **plain TCP** (ChaCha20-Poly1305, X25519, RSA-PSS). |
| **Same language / same course constraints** | One Python codebase, `cryptography` for certs, stdlib `ssl` for bulk path. | Reuses same PEM trust material; different code path = clearer exam narrative. |
| **CIAA story is clean** | C/I from TLS + file hash; A from mTLS; A from TCP + resume. | C/I from AEAD + file hash; A from certs + signatures; A from TCP + resume. |
| **Rubric “not just tweak cipher suite”** | Changing AES-GCM to ChaCha in TLS would be cosmetic; **switching entire security layer** is not. | Proves you can secure a protocol **without** wrapping the bulk data in TLS. |

**Bottom line:** the pair **maximizes contrast** (where the AEAD “lives” and how keys are established for the file bytes) while staying **TCP-only**, **library crypto**, and **implementable** in a short window.

---

## How to use this file for grading

- Copy rows from the **table** into your official `AI_NOTES.md` if your instructor wants “prompt → outcome.”  
- Edit any row to match **your exact wording** if you kept a separate chat log.  
- Add timestamps and **4 GB** hash evidence in `AI_NOTES.md` under “Evidence you actually ran the code.”

---

## Related files

- `AI_NOTES.md` — course template + placeholders (link this doc from there if you like).  
- `documentation/documentation-steps.txt` — operational runbook.  
- `DESIGN.md` — architecture + threat model tables.
