"""Unit tests for src/runners/inventory_runner.py."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.runners.inventory_runner import InventoryRunner
from tests.unit.runner_test_context import build_gate_context


def test_inventory_runner_execute_writes_merged_json(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    ctx = build_gate_context(tmp_path, fixtures, run_id="RUN-INV")
    inv = tmp_path / "inventory" / "cmdb"
    inv.mkdir(parents=True)
    f = inv / "host.json"
    f.write_text("{}", encoding="utf-8")

    runner = InventoryRunner(ctx)
    out_dir = tmp_path / "out"
    paths = runner.run(["192.168.56.10"], out_dir)

    assert len(paths) == 1
    data = json.loads(paths[0].read_text(encoding="utf-8"))
    assert data["targets"] == ["192.168.56.10"]
    assert "cmdb" in data["sources"]
    assert any("host.json" in p for p in data["sources"]["cmdb"])
