"""Small .env loader for local pipeline execution.

Supports:
- KEY=value
- export KEY=value
- single/double quoted values
- shell-style variable expansion, e.g. PATH="$HOME/.local/bin:$PATH"

This avoids requiring python-dotenv as a dependency.
"""

from __future__ import annotations

import os
import re
import shlex
from pathlib import Path

_ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _parse_env_value(raw_value: str, *, line_number: int) -> str:
    value = raw_value.strip()

    if value == "":
        return ""

    try:
        parts = shlex.split(value, comments=True, posix=True)
    except ValueError as exc:
        raise ValueError(f"Invalid .env value on line {line_number}: {exc}") from exc

    if not parts:
        parsed = ""
    elif len(parts) == 1:
        parsed = parts[0]
    else:
        parsed = " ".join(parts)

    return os.path.expandvars(parsed)


def load_env_file(path: str | Path, *, override: bool = True) -> dict[str, str]:
    """Load key-value pairs from a .env file into os.environ.

    Args:
        path: Path to the .env file.
        override: If true, values from the .env file override existing variables.

    Returns:
        Dictionary of loaded environment values.

    Raises:
        ValueError: If a non-empty/non-comment line is malformed.
    """

    env_path = Path(path)

    if not env_path.exists():
        return {}

    loaded: dict[str, str] = {}

    for line_number, raw_line in enumerate(
        env_path.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        if line.startswith("export "):
            line = line.removeprefix("export ").strip()

        if "=" not in line:
            raise ValueError(f"Invalid .env line {line_number}: missing '='")

        raw_key, raw_value = line.split("=", 1)
        key = raw_key.strip()

        if not _ENV_KEY_RE.fullmatch(key):
            raise ValueError(f"Invalid .env key on line {line_number}: {key!r}")

        value = _parse_env_value(raw_value, line_number=line_number)

        if override or key not in os.environ:
            os.environ[key] = value

        loaded[key] = os.environ[key]

    return loaded
