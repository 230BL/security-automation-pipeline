"""Unit tests for src/runners/prowler_runner.py."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.orchestrator.exceptions import RunnerError
from src.runners.prowler_runner import ProwlerRunner
from tests.unit.runner_test_context import build_gate_context


def test_prowler_stub_without_binary(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = build_gate_context(tmp_path, fixtures, run_id="RUN-PR")
    monkeypatch.setattr("src.runners.prowler_runner.shutil.which", lambda *_: None)
    paths = ProwlerRunner(ctx).run([], tmp_path / "out")
    assert len(paths) == 1
    data = json.loads(paths[0].read_text(encoding="utf-8"))
    assert data == []


def test_prowler_invokes_binary(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = build_gate_context(tmp_path, fixtures, run_id="RUN-PR")
    monkeypatch.setattr("src.runners.prowler_runner.shutil.which", lambda *_: "/bin/prowler")
    mock_run = MagicMock(return_value=MagicMock(returncode=0, stdout="", stderr=""))
    monkeypatch.setattr("src.runners.prowler_runner.subprocess.run", mock_run)
    paths = ProwlerRunner(ctx, {"prowler": {"provider": "aws"}}).run([], tmp_path / "out")
    assert len(paths) == 1
    exe = mock_run.call_args[1]["executable"]
    assert exe == "/bin/prowler"


def test_prowler_failure_raises(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    monkeypatch.setattr("src.runners.prowler_runner.shutil.which", lambda *_: "/bin/prowler")
    monkeypatch.setattr(
        "src.runners.prowler_runner.subprocess.run",
        lambda *_a, **_k: MagicMock(returncode=1, stdout="", stderr="x"),
    )
    with pytest.raises(RunnerError, match="Prowler failed"):
        ProwlerRunner(ctx).run([], tmp_path / "out")
