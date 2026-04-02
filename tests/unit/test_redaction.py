from __future__ import annotations

from src.utils.redaction import REDACTED, redact_dict, redact_string


def test_redact_string_headers() -> None:
    s = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789"
    out = redact_string(s)
    assert REDACTED in out


def test_redact_dict_recursive_non_mutating() -> None:
    original = {
        "user": "alice",
        "password": "secret",
        "nested": {"token": "t0k3n", "ok": "value"},
        "list": [{"api_key": "k"}, "Bearer abc"],
    }
    copy_before = dict(original)
    redacted = redact_dict(original)

    assert original == copy_before
    assert redacted["password"] == REDACTED
    assert redacted["nested"]["token"] == REDACTED
    assert redacted["nested"]["ok"] == "value"
    assert redacted["list"][0]["api_key"] == REDACTED
    assert REDACTED in redacted["list"][1]
