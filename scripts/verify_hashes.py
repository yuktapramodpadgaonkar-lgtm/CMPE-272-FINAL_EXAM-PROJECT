#!/usr/bin/env python3
"""Compare SHA-256 of two files (streaming). Exit 0 if equal, 1 otherwise."""
from __future__ import annotations

import argparse
import hashlib
import pathlib
import sys

CHUNK = 1024 * 1024


def sha256_stream(path: pathlib.Path) -> bytes:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            b = f.read(CHUNK)
            if not b:
                break
            h.update(b)
    return h.digest()


def main() -> int:
    ap = argparse.ArgumentParser(description="Compare SHA-256 of two files (streaming).")
    ap.add_argument("source", type=pathlib.Path, help="Original file (e.g. test_4gb.bin)")
    ap.add_argument("received", type=pathlib.Path, help="Received file (e.g. received_a.bin)")
    args = ap.parse_args()

    for p in (args.source, args.received):
        if not p.is_file():
            print(f"error: not a file: {p}", file=sys.stderr)
            return 2

    a = sha256_stream(args.source)
    b = sha256_stream(args.received)
    ha, hb = a.hex(), b.hex()

    if a == b:
        print(f"OK: SHA-256 match\n  {ha}")
        return 0

    print("FAIL: SHA-256 mismatch", file=sys.stderr)
    print(f"  source:   {ha}", file=sys.stderr)
    print(f"  received: {hb}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
