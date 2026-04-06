"""Unit tests for src/runners/scoutsuite_runner.py."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.orchestrator.exceptions import RunnerError, RunnerHealthError
from src.runners.scoutsuite_runner import ScoutSuiteRunner
from tests.unit.runner_test_context import build_gate_context


def _set_aws_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test-access-key")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test-secret-key")
    monkeypatch.delenv("AWS_PROFILE", raising=False)


def test_scoutsuite_health_fails_without_binary_and_credentials(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    monkeypatch.setattr("src.runners.scoutsuite_runner.shutil.which", lambda *_: None)
    assert ScoutSuiteRunner(ctx).health_check() is False


def test_scoutsuite_get_version_missing_exe(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    monkeypatch.setattr("src.runners.scoutsuite_runner.shutil.which", lambda *_: None)
    assert ScoutSuiteRunner(ctx).get_version() == "missing:scoutsuite"


def test_scoutsuite_run_healthcheck_failure_when_not_configured(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    monkeypatch.setattr("src.runners.scoutsuite_runner.shutil.which", lambda *_: None)

    with pytest.raises(RunnerHealthError, match="scoutsuite health check failed"):
        ScoutSuiteRunner(ctx).run([], tmp_path / "out")


def test_scoutsuite_success_returns_jsons(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    _set_aws_env(monkeypatch)

    monkeypatch.setattr(
        "src.runners.scoutsuite_runner.shutil.which",
        lambda *_: "/bin/scout",
    )

    out = tmp_path / "out"
    report_dir = out / "scoutsuite_report"
    report_dir.mkdir(parents=True)

    report_json = report_dir / "a.json"
    report_json.write_text('{"ok": true}', encoding="utf-8")

    mock_run = MagicMock(return_value=MagicMock(returncode=0, stdout="", stderr=""))
    monkeypatch.setattr("src.runners.scoutsuite_runner.subprocess.run", mock_run)

    paths = ScoutSuiteRunner(ctx).run([], out)
    assert paths == [report_json]


def test_scoutsuite_failure_raises(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    _set_aws_env(monkeypatch)

    monkeypatch.setattr(
        "src.runners.scoutsuite_runner.shutil.which",
        lambda *_: "/bin/scout",
    )
    monkeypatch.setattr(
        "src.runners.scoutsuite_runner.subprocess.run",
        lambda *_a, **_k: MagicMock(returncode=1, stdout="", stderr="e"),
    )

    with pytest.raises(RunnerError, match="ScoutSuite failed"):
        ScoutSuiteRunner(ctx).run([], tmp_path / "out")


def test_scoutsuite_no_json_after_success_raises(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    _set_aws_env(monkeypatch)

    monkeypatch.setattr(
        "src.runners.scoutsuite_runner.shutil.which",
        lambda *_: "/bin/scout",
    )
    monkeypatch.setattr(
        "src.runners.scoutsuite_runner.subprocess.run",
        lambda *_a, **_k: MagicMock(returncode=0, stdout="", stderr=""),
    )

    with pytest.raises(
        RunnerError, match="ScoutSuite completed but produced no JSON report artifacts"
    ):
        ScoutSuiteRunner(ctx).run([], tmp_path / "out")
