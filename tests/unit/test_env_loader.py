"""Unit tests for src/utils/env_loader.py."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from src.utils.env_loader import load_env_file


def test_load_env_file_missing_returns_empty(tmp_path: Path) -> None:
    assert load_env_file(tmp_path / ".env") == {}


def test_load_env_file_loads_plain_and_export_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "PLAIN=value\n"
        "export EXPORTED=ok\n"
        "SINGLE_QUOTED='secret value'\n"
        'DOUBLE_QUOTED="hello world"\n',
        encoding="utf-8",
    )

    for key in ["PLAIN", "EXPORTED", "SINGLE_QUOTED", "DOUBLE_QUOTED"]:
        monkeypatch.delenv(key, raising=False)

    loaded = load_env_file(env_file)

    assert loaded["PLAIN"] == "value"
    assert loaded["EXPORTED"] == "ok"
    assert loaded["SINGLE_QUOTED"] == "secret value"
    assert loaded["DOUBLE_QUOTED"] == "hello world"
    assert os.environ["PLAIN"] == "value"
    assert os.environ["EXPORTED"] == "ok"


def test_load_env_file_expands_existing_environment_variables(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text('PATH="$HOME/.local/bin:$PATH"\n', encoding="utf-8")

    monkeypatch.setenv("HOME", "/home/brahim")
    monkeypatch.setenv("PATH", "/usr/bin")

    loaded = load_env_file(env_file)

    assert loaded["PATH"] == "/home/brahim/.local/bin:/usr/bin"
    assert os.environ["PATH"] == "/home/brahim/.local/bin:/usr/bin"


def test_load_env_file_respects_no_override(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("DEFECTDOJO_URL=http://from-file\n", encoding="utf-8")

    monkeypatch.setenv("DEFECTDOJO_URL", "http://existing")

    loaded = load_env_file(env_file, override=False)

    assert loaded["DEFECTDOJO_URL"] == "http://existing"
    assert os.environ["DEFECTDOJO_URL"] == "http://existing"


def test_load_env_file_override_true_replaces_existing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("DEFECTDOJO_URL=http://from-file\n", encoding="utf-8")

    monkeypatch.setenv("DEFECTDOJO_URL", "http://existing")

    loaded = load_env_file(env_file, override=True)

    assert loaded["DEFECTDOJO_URL"] == "http://from-file"
    assert os.environ["DEFECTDOJO_URL"] == "http://from-file"


def test_load_env_file_rejects_invalid_line(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("BROKEN_LINE\n", encoding="utf-8")

    with pytest.raises(ValueError, match="missing '='"):
        load_env_file(env_file)


def test_load_env_file_rejects_invalid_key(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("1BAD=value\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Invalid .env key"):
        load_env_file(env_file)


def test_load_env_file_rejects_unclosed_quote(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text('BAD="unterminated\n', encoding="utf-8")

    with pytest.raises(ValueError, match="Invalid .env value"):
        load_env_file(env_file)
