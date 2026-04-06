from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from src.orchestrator import main as orchestrator_main


def test_load_yaml_missing_returns_empty(tmp_path: Path) -> None:
    missing = tmp_path / "missing.yml"
    assert orchestrator_main.load_yaml(missing) == {}


def test_load_yaml_mapping_returns_dict(tmp_path: Path) -> None:
    path = tmp_path / "config.yml"
    path.write_text("name: lab\ncount: 2\n", encoding="utf-8")

    assert orchestrator_main.load_yaml(path) == {
        "name": "lab",
        "count": 2,
    }


def test_load_yaml_non_mapping_returns_empty(tmp_path: Path) -> None:
    path = tmp_path / "config.yml"
    path.write_text("- a\n- b\n", encoding="utf-8")

    assert orchestrator_main.load_yaml(path) == {}


def test_gate_only_calls_run_gate_and_setup_logging(
    monkeypatch,
    tmp_path: Path,
) -> None:
    captured: dict[str, object] = {}

    ctx = SimpleNamespace(
        run_metadata=SimpleNamespace(run_id="RUN-GATE-ONLY"),
    )

    def fake_run_gate(**kwargs):
        captured["gate_kwargs"] = kwargs
        return ctx

    def fake_setup_logging(run_id: str) -> None:
        captured["run_id"] = run_id

    monkeypatch.setattr(orchestrator_main, "run_gate", fake_run_gate)
    monkeypatch.setattr(orchestrator_main, "setup_logging", fake_setup_logging)

    result = orchestrator_main.gate_only(
        manifest_path=tmp_path / "scope_manifest.yml",
        workflow="lab_poc",
        environment="lab",
        base_dir=tmp_path,
    )

    assert result is ctx
    assert captured["run_id"] == "RUN-GATE-ONLY"
    assert captured["gate_kwargs"] == {
        "manifest_path": tmp_path / "scope_manifest.yml",
        "base_dir": tmp_path,
        "workflow": "lab_poc",
        "environment": "lab",
    }
