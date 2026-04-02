"""Evidence redaction for secrets, tokens, and sensitive values.

Redacts known-sensitive patterns from strings and recursively from
dictionary values. Never mutates the original data.
"""

from __future__ import annotations

import copy
import re
from typing import Any, cast

REDACTED = "[REDACTED]"

SENSITIVE_KEYS: set[str] = {
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "api-key",
    "access_token",
    "refresh_token",
    "session",
    "cookie",
    "authorization",
    "auth",
    "credential",
    "private_key",
    "secret_key",
    "aws_secret_access_key",
    "aws_session_token",
    "client_secret",
}

SENSITIVE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key)\s*[=:]\s*\S+"),
    re.compile(r"(?i)bearer\s+[a-zA-Z0-9._~+/=-]+"),
    re.compile(r"(?i)basic\s+[a-zA-Z0-9+/]+=*"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)ghp_[a-zA-Z0-9]{36}"),
    re.compile(r"(?i)sk-[a-zA-Z0-9]{32,}"),
]


def add_sensitive_patterns(patterns: list[str]) -> None:
    """Add additional regex patterns for redaction at runtime."""
    for p in patterns:
        SENSITIVE_PATTERNS.append(re.compile(p))


def redact_string(value: str) -> str:
    """Redact known sensitive patterns from a string value."""
    result = value
    for pattern in SENSITIVE_PATTERNS:
        result = pattern.sub(REDACTED, result)
    return result


def redact_dict(data: dict[str, Any]) -> dict[str, Any]:
    """Recursively redact sensitive values from a dictionary. Returns a new dict."""
    # _redact_value preserves the dictionary structure when given a dict[str, Any]
    return cast(dict[str, Any], _redact_value(copy.deepcopy(data)))


def _redact_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _redact_key_value(k, v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    if isinstance(value, str):
        return redact_string(value)
    return value


def _redact_key_value(key: str, value: Any) -> Any:
    if key.lower() in SENSITIVE_KEYS:
        if isinstance(value, dict):
            return {k: REDACTED for k in value}
        return REDACTED
    return _redact_value(value)
