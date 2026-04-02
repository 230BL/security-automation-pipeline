"""Unit tests for src/runners/zap_runner.py."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.orchestrator.exceptions import EnvironmentMismatchError, RunnerError
from src.runners.zap_runner import ZapRunner
from tests.unit.runner_test_context import build_gate_context


def test_zap_skips_non_web_target(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    monkeypatch.setattr("src.runners.zap_runner.shutil.which", lambda *_: "/bin/docker")
    monkeypatch.setattr(ZapRunner, "_image_available", lambda self, d: True)
    mock_run = MagicMock(return_value=MagicMock(returncode=0, stdout="", stderr=""))
    monkeypatch.setattr("src.runners.zap_runner.subprocess.run", mock_run)
    paths = ZapRunner(ctx).run(["192.168.56.10"], tmp_path / "out")
    assert len(paths) == 1
    assert not any("zap-baseline.py" in str(c) for c in mock_run.call_args_list)


def test_zap_active_mode_blocked_outside_staging(tmp_path: Path, fixtures: Path) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    ctx.run_metadata.environment = "prod"
    out = tmp_path / "out"
    out.mkdir(parents=True, exist_ok=True)
    with pytest.raises(EnvironmentMismatchError):
        ZapRunner(ctx, {"zap": {"mode": "active"}}).execute(["https://example.com/"], out)


def test_zap_no_docker_stub(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    monkeypatch.setattr("src.runners.zap_runner.shutil.which", lambda *_: None)
    paths = ZapRunner(ctx).run(["https://example.com/"], tmp_path / "out")
    assert len(paths) == 1


def test_zap_image_not_available_stub(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    monkeypatch.setattr("src.runners.zap_runner.shutil.which", lambda *_: "/bin/docker")
    monkeypatch.setattr(ZapRunner, "_image_available", lambda self, d: False)
    paths = ZapRunner(ctx).run(["https://example.com/"], tmp_path / "out")
    assert len(paths) == 1


def test_zap_baseline_docker_success(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    monkeypatch.setattr("src.runners.zap_runner.shutil.which", lambda *_: "/bin/docker")
    monkeypatch.setattr(ZapRunner, "_image_available", lambda self, d: True)
    mock_run = MagicMock(return_value=MagicMock(returncode=0, stdout="", stderr=""))
    monkeypatch.setattr("src.runners.zap_runner.subprocess.run", mock_run)
    out = tmp_path / "out"
    paths = ZapRunner(ctx, {"zap": {"mode": "baseline"}}).run(["https://example.com/"], out)
    assert len(paths) == 1
    assert any("zap-baseline.py" in str(c) for c in mock_run.call_args_list)


def test_zap_docker_failure_raises(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    monkeypatch.setattr("src.runners.zap_runner.shutil.which", lambda *_: "/bin/docker")
    monkeypatch.setattr(ZapRunner, "_image_available", lambda self, d: True)
    mock_run = MagicMock(return_value=MagicMock(returncode=1, stdout="", stderr="bad"))
    monkeypatch.setattr("src.runners.zap_runner.subprocess.run", mock_run)
    with pytest.raises(RunnerError, match="ZAP failed"):
        ZapRunner(ctx).run(["https://example.com/"], tmp_path / "out")
