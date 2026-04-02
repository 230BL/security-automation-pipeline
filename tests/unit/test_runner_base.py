"""Unit tests for src/runners/base.py."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.orchestrator.exceptions import RunnerError, RunnerHealthError, TargetOutOfScopeError
from src.runners.base import BaseRunner
from tests.unit.runner_test_context import build_gate_context


class _FakeRunner(BaseRunner):
    tool_name = "fake"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._execute_result: list[Path] = []
        self._healthy = True
        self._version = "1.0.0"

    def execute(self, targets: list[str], output_dir: Path) -> list[Path]:
        return list(self._execute_result)

    def health_check(self) -> bool:
        return self._healthy

    def get_version(self) -> str:
        return self._version


def test_base_runner_stores_config_and_artifacts(tmp_path: Path, fixtures: Path) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    r = _FakeRunner(ctx, {"k": "v"})
    assert r.config == {"k": "v"}
    assert r.artifacts == []


def test_run_success_path(tmp_path: Path, fixtures: Path) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    out_dir = tmp_path / "out"
    r = _FakeRunner(ctx)
    artifact = out_dir / "a.txt"
    r._execute_result = [artifact]
    paths = r.run(["192.168.56.10"], out_dir)
    assert paths == [artifact]
    assert r.artifacts == [artifact]
    assert out_dir.is_dir()


def test_run_health_check_failure(tmp_path: Path, fixtures: Path) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    r = _FakeRunner(ctx)
    r._healthy = False
    with pytest.raises(RunnerHealthError):
        r.run(["192.168.56.10"], tmp_path / "out")


def test_run_target_count_exceeds_ceiling(tmp_path: Path, fixtures: Path) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    r = _FakeRunner(ctx)
    many = ["192.168.56.10"] * 20
    with pytest.raises(TargetOutOfScopeError):
        r.run(many, tmp_path / "out")


def test_run_with_maintenance_window(tmp_path: Path, fixtures: Path) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    r = _FakeRunner(ctx)
    out_dir = tmp_path / "out"
    r._execute_result = [out_dir / "x"]
    paths = r.run(["192.168.56.10"], out_dir, window_name="always_open")
    assert paths == [out_dir / "x"]


class _ExplodingRunner(_FakeRunner):
    def execute(self, targets: list[str], output_dir: Path) -> list[Path]:
        raise RuntimeError("tool crashed")


def test_run_execute_exception_wraps_runner_error(tmp_path: Path, fixtures: Path) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    r = _ExplodingRunner(ctx)
    with pytest.raises(RunnerError) as ei:
        r.run(["192.168.56.10"], tmp_path / "out")
    assert "fake" in str(ei.value).lower() or "execution failed" in str(ei.value).lower()
