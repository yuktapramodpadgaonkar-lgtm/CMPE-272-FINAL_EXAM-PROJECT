#!/usr/bin/env python3
"""Stream a SHA-256 digest for huge files without loading them into RAM."""
from __future__ import annotations

import argparse
import hashlib
import pathlib
import sys

CHUNK = 1024 * 1024


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("path", type=pathlib.Path)
    args = ap.parse_args()
    h = hashlib.sha256()
    with args.path.open("rb") as f:
        while True:
            b = f.read(CHUNK)
            if not b:
                break
            h.update(b)
    print(h.hexdigest())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
