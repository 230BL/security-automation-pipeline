#!/usr/bin/env python3
"""Generate a deterministic SHA-256 hash for the current allowlist file."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.utils.hashing import hash_file  # noqa: E402


def main() -> int:
    p = argparse.ArgumentParser(description="Hash allowlist file")
    p.add_argument("--allowlist", default="scope/allowlist.txt", help="Allowlist file path")
    args = p.parse_args()
    path = ROOT / args.allowlist
    if not path.exists():
        raise SystemExit(f"Allowlist not found: {path}")
    sys.stdout.write(f"{hash_file(path)}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
