"""Unit tests for src/runners/greenbone_runner.py."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.runners.greenbone_runner import GreenboneRunner
from tests.unit.runner_test_context import build_gate_context


def test_greenbone_execute_writes_csv(tmp_path: Path, fixtures: Path) -> None:
    ctx = build_gate_context(tmp_path, fixtures, run_id="RUN-GB")
    r = GreenboneRunner(ctx, {"greenbone": {"max_concurrent_hosts": 2}})
    out = tmp_path / "out"
    paths = r.run(["10.0.0.1", "10.0.0.2", "10.0.0.3"], out)  # allowlisted in runner_test_context
    assert len(paths) == 1
    text = paths[0].read_text(encoding="utf-8")
    assert "Greenbone stub" in text
    assert "10.0.0.1" in text and "10.0.0.2" in text
    assert "10.0.0.3" not in text


def test_greenbone_get_version_stub(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    r = GreenboneRunner(ctx)
    monkeypatch.setattr("src.runners.greenbone_runner.shutil.which", lambda *_: None)
    assert r.get_version() == "stub"


def test_greenbone_get_version_from_exe(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    r = GreenboneRunner(ctx)
    monkeypatch.setattr(
        "src.runners.greenbone_runner.shutil.which",
        lambda name: "/bin/gvm-cli" if name == "gvm-cli" else None,
    )
    mock_run = MagicMock(return_value=MagicMock(stdout="1.0\n", stderr="", returncode=0))
    monkeypatch.setattr("src.runners.greenbone_runner.subprocess.run", mock_run)
    assert r.get_version() == "1.0"
