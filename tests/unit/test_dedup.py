from __future__ import annotations

from src.scoring.dedup import deduplicate


def test_dedup_keeps_highest_score() -> None:
    fp = "a" * 64
    findings = [
        {"fingerprint": fp, "title": "t", "composite_score": 2.0},
        {"fingerprint": fp, "title": "t", "composite_score": 9.0},
    ]
    out = deduplicate(findings)
    assert len(out) == 1
    assert out[0]["composite_score"] == 9.0
