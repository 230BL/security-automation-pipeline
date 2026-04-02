from __future__ import annotations

from pathlib import Path

from src.utils.hashing import hash_file, hash_string, hash_targets, verify_hash


def test_hash_string_deterministic() -> None:
    assert hash_string("abc") == hash_string("abc")
    assert hash_string("abc") != hash_string("abcd")


def test_hash_targets_sorted_deduped() -> None:
    h1 = hash_targets(["B.COM", "a.com", "a.com "])
    h2 = hash_targets(["a.com", "b.com"])
    assert h1 == h2


def test_hash_file_and_verify(tmp_path: Path) -> None:
    p = tmp_path / "a.txt"
    p.write_text("hello", encoding="utf-8")
    digest = hash_file(p)
    assert verify_hash(p, digest) is True
    assert verify_hash(p, "0" * 64) is False
