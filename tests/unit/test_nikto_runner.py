"""Unit tests for src/runners/nikto_runner.py."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.orchestrator.exceptions import RunnerError
from src.runners.nikto_runner import NiktoRunner
from tests.unit.runner_test_context import build_gate_context


def test_nikto_stub_without_binary(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    monkeypatch.setattr("src.runners.nikto_runner.shutil.which", lambda *_: None)
    r = NiktoRunner(ctx)
    paths = r.run(["http://192.168.56.10/"], tmp_path / "out")
    assert len(paths) == 1
    assert paths[0].name == "nikto_0.json"


def test_nikto_subprocess_success(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    monkeypatch.setattr("src.runners.nikto_runner.shutil.which", lambda *_: "/usr/bin/nikto")
    mock_run = MagicMock(return_value=MagicMock(returncode=0, stdout="", stderr=""))
    monkeypatch.setattr("src.runners.nikto_runner.subprocess.run", mock_run)
    r = NiktoRunner(ctx)
    out = tmp_path / "out"
    paths = r.run(["http://192.168.56.10/"], out)
    assert len(paths) == 1
    cmd = mock_run.call_args[0][0]
    assert cmd[0] == "/usr/bin/nikto"
    assert "-h" in cmd


def test_nikto_subprocess_failure_raises(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    monkeypatch.setattr("src.runners.nikto_runner.shutil.which", lambda *_: "/usr/bin/nikto")
    mock_run = MagicMock(return_value=MagicMock(returncode=2, stdout="", stderr="oh no"))
    monkeypatch.setattr("src.runners.nikto_runner.subprocess.run", mock_run)
    with pytest.raises(RunnerError, match="Nikto failed"):
        NiktoRunner(ctx).run(["http://192.168.56.10/"], tmp_path / "out")
