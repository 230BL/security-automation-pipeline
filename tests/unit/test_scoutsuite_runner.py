"""Unit tests for src/runners/scoutsuite_runner.py."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.orchestrator.exceptions import RunnerError
from src.runners.scoutsuite_runner import ScoutSuiteRunner
from tests.unit.runner_test_context import build_gate_context


def test_scoutsuite_stub_without_scout(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    monkeypatch.setattr("src.runners.scoutsuite_runner.shutil.which", lambda *_: None)
    paths = ScoutSuiteRunner(ctx).run([], tmp_path / "out")
    assert len(paths) == 1
    assert paths[0].name == "scoutsuite_stub.json"
    assert json.loads(paths[0].read_text(encoding="utf-8")) == {"findings": []}


def test_scoutsuite_success_returns_jsons(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    monkeypatch.setattr("src.runners.scoutsuite_runner.shutil.which", lambda *_: "/bin/scout")
    mock_run = MagicMock(return_value=MagicMock(returncode=0, stdout="", stderr=""))
    monkeypatch.setattr("src.runners.scoutsuite_runner.subprocess.run", mock_run)
    out = tmp_path / "out"
    report_dir = out / "scoutsuite_report"
    report_dir.mkdir(parents=True)
    j = report_dir / "a.json"
    j.write_text("{}", encoding="utf-8")
    paths = ScoutSuiteRunner(ctx).run([], out)
    assert paths == [j]


def test_scoutsuite_failure_raises(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    monkeypatch.setattr("src.runners.scoutsuite_runner.shutil.which", lambda *_: "/bin/scout")
    monkeypatch.setattr(
        "src.runners.scoutsuite_runner.subprocess.run",
        lambda *_a, **_k: MagicMock(returncode=1, stdout="", stderr="e"),
    )
    with pytest.raises(RunnerError, match="ScoutSuite failed"):
        ScoutSuiteRunner(ctx).run([], tmp_path / "out")


def test_scoutsuite_no_json_after_success_returns_empty(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    monkeypatch.setattr("src.runners.scoutsuite_runner.shutil.which", lambda *_: "/bin/scout")
    monkeypatch.setattr(
        "src.runners.scoutsuite_runner.subprocess.run",
        lambda *_a, **_k: MagicMock(returncode=0, stdout="", stderr=""),
    )
    paths = ScoutSuiteRunner(ctx).run([], tmp_path / "out")
    assert paths == []
