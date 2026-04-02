"""Unit tests for src/runners/wazuh_runner.py."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.orchestrator.exceptions import RunnerError
from src.runners.wazuh_runner import WazuhRunner
from tests.unit.runner_test_context import build_gate_context


def test_wazuh_drop_mode_stub(tmp_path: Path, fixtures: Path) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    drop = tmp_path / "wazuh_drop"
    r = WazuhRunner(ctx, {"wazuh": {"drop_dir": str(drop), "mode": "drop"}})
    paths = r.run([], tmp_path / "out")
    assert len(paths) == 1
    assert paths[0].name == "wazuh_empty_findings.json"


def test_wazuh_drop_mode_collects_json(tmp_path: Path, fixtures: Path) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    drop = tmp_path / "wazuh_drop"
    drop.mkdir()
    j = drop / "a.json"
    j.write_text("{}", encoding="utf-8")
    r = WazuhRunner(ctx, {"wazuh": {"drop_dir": str(drop)}})
    paths = r.run([], tmp_path / "out")
    assert paths == [j]


def test_wazuh_api_mode_success(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    session = MagicMock()
    resp = MagicMock()
    resp.json.return_value = {"data": {"affected_items": []}}
    resp.raise_for_status = MagicMock()
    session.get.return_value = resp

    monkeypatch.setattr("src.runners.wazuh_runner.requests.Session", lambda: session)
    r = WazuhRunner(
        ctx,
        {
            "wazuh": {
                "mode": "api",
                "api_url": "https://wazuh.example",
                "api_token": "tok",
            }
        },
    )
    out = tmp_path / "out"
    paths = r.run([], out)
    assert len(paths) == 2
    for p in paths:
        data = json.loads(p.read_text(encoding="utf-8"))
        assert data == {"data": {"affected_items": []}}


def test_wazuh_api_missing_config_raises(tmp_path: Path, fixtures: Path) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    r = WazuhRunner(ctx, {"wazuh": {"mode": "api", "api_url": "", "api_token": ""}})
    with pytest.raises(RunnerError, match="api_url"):
        r.run([], tmp_path / "out")


def test_wazuh_api_request_failure_wraps(
    tmp_path: Path, fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = build_gate_context(tmp_path, fixtures)
    session = MagicMock()
    session.get.side_effect = ConnectionError("nope")
    monkeypatch.setattr("src.runners.wazuh_runner.requests.Session", lambda: session)
    r = WazuhRunner(
        ctx,
        {"wazuh": {"mode": "api", "api_url": "https://w.example", "api_token": "t"}},
    )
    with pytest.raises(RunnerError, match="Wazuh API"):
        r.run([], tmp_path / "out")
