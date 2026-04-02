"""Unit tests for src/orchestrator/main.py."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import yaml

from src.orchestrator.gate import GateContext
from src.orchestrator.main import gate_only, load_yaml


def test_load_yaml_missing_returns_empty(tmp_path: Path) -> None:
    assert load_yaml(tmp_path / "nope.yml") == {}


def test_load_yaml_reads_mapping(tmp_path: Path) -> None:
    p = tmp_path / "cfg.yml"
    p.write_text(yaml.safe_dump({"a": 1}), encoding="utf-8")
    assert load_yaml(p) == {"a": 1}


def test_load_yaml_non_mapping_returns_empty(tmp_path: Path) -> None:
    p = tmp_path / "scalar.yml"
    p.write_text("just a string\n", encoding="utf-8")
    assert load_yaml(p) == {}


@patch("src.orchestrator.main.setup_logging")
@patch("src.orchestrator.main.run_gate")
def test_gate_only_calls_gate_and_logging(
    mock_run_gate: MagicMock,
    mock_setup_logging: MagicMock,
    tmp_path: Path,
    fixtures: Path,
) -> None:
    ctx = MagicMock(spec=GateContext)
    ctx.run_metadata = MagicMock(run_id="RUN-MOCK")
    mock_run_gate.return_value = ctx

    out = gate_only(
        manifest_path=fixtures / "scope" / "valid_manifest.yml",
        workflow="lab_poc",
        environment="lab",
        base_dir=tmp_path,
    )

    assert out is ctx
    mock_run_gate.assert_called_once()
    mock_setup_logging.assert_called_once_with("RUN-MOCK")
