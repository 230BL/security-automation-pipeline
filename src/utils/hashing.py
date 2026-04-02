"""Deterministic hashing utilities for scope verification and evidence integrity."""

from __future__ import annotations

import hashlib
from pathlib import Path


def hash_file(path: Path, algorithm: str = "sha256") -> str:
    """Compute hex digest of a file. Reads in 8KB chunks for memory safety."""
    h = hashlib.new(algorithm)
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def hash_string(value: str, algorithm: str = "sha256") -> str:
    """Compute hex digest of a UTF-8 string."""
    return hashlib.new(algorithm, value.encode("utf-8")).hexdigest()


def hash_targets(targets: list[str], algorithm: str = "sha256") -> str:
    """Compute a deterministic hash over a sorted, deduplicated target list."""
    normalized = sorted(set(t.strip().lower() for t in targets if t.strip()))
    combined = "\n".join(normalized)
    return hash_string(combined, algorithm)


def verify_hash(path: Path, expected: str, algorithm: str = "sha256") -> bool:
    """Verify a file's hash matches the expected value. Returns bool, does not raise."""
    actual = hash_file(path, algorithm)
    return actual == expected
