"""Unit tests for src/runners/osquery_runner.py."""

from __future__ import annotations

import json
from pathlib import Path

from src.runners.osquery_runner import OsqueryRunner
from tests.unit.runner_test_context import build_gate_context


def test_osquery_runner_stub_when_no_json_files(tmp_path: Path, fixtures: Path) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    drop = tmp_path / "empty_osquery"
    osq = OsqueryRunner(ctx, {"osquery": {"drop_dir": str(drop)}})
    out_dir = tmp_path / "out"
    paths = osq.run(["192.168.56.10"], out_dir)
    assert len(paths) == 1
    assert paths[0].name == "osquery_empty.json"
    data = json.loads(paths[0].read_text(encoding="utf-8"))
    assert data == {"findings": []}


def test_osquery_runner_collects_drop_json(tmp_path: Path, fixtures: Path) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    drop = tmp_path / "osq_drop"
    drop.mkdir(parents=True)
    j = drop / "a" / "b.json"
    j.parent.mkdir(parents=True)
    j.write_text("{}", encoding="utf-8")

    osq = OsqueryRunner(ctx, {"osquery": {"drop_dir": str(drop)}})
    paths = osq.run(["192.168.56.10"], tmp_path / "out")
    assert paths == [j]
