from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml

from src.orchestrator.exceptions import (
    MaintenanceWindowError,
    TargetOutOfScopeError,
    WorkflowNotApprovedError,
)
from src.orchestrator.gate import run_gate


def _write_scope(tmp_path: Path, manifest: dict[str, Any], allowlist: str) -> Path:
    scope_dir = tmp_path / "scope"
    scope_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = scope_dir / "scope_manifest.yml"
    manifest_path.write_text(yaml.safe_dump(manifest), encoding="utf-8")
    (scope_dir / "allowlist.txt").write_text(allowlist, encoding="utf-8")
    return manifest_path


def test_gate_passes_in_lab_mode(tmp_path: Path, fixtures: Path) -> None:
    manifest = yaml.safe_load(
        (fixtures / "scope" / "valid_manifest.yml").read_text(encoding="utf-8")
    )
    manifest_path = _write_scope(tmp_path, manifest, "192.168.56.10\n")
    cfg = {"lab_mode": True}
    ctx = run_gate(
        manifest_path=manifest_path,
        base_dir=tmp_path,
        workflow="lab_poc",
        environment="lab",
        now=datetime(2026, 1, 1, tzinfo=UTC),
        config=cfg,
    )
    assert ctx.validated_targets == ["192.168.56.10"]


def test_gate_blocks_unapproved_workflow(tmp_path: Path, fixtures: Path) -> None:
    manifest = yaml.safe_load(
        (fixtures / "scope" / "valid_manifest.yml").read_text(encoding="utf-8")
    )
    manifest_path = _write_scope(tmp_path, manifest, "192.168.56.10\n")
    with pytest.raises(WorkflowNotApprovedError):
        run_gate(
            manifest_path=manifest_path,
            base_dir=tmp_path,
            workflow="not-approved",
            environment="lab",
            now=datetime(2026, 1, 1, tzinfo=UTC),
            config={"lab_mode": True},
        )


def test_gate_blocks_out_of_scope_target(tmp_path: Path, fixtures: Path) -> None:
    manifest = yaml.safe_load(
        (fixtures / "scope" / "valid_manifest.yml").read_text(encoding="utf-8")
    )
    manifest["targets"]["asset_classes"][0]["cidrs"] = ["10.0.0.99"]
    manifest_path = _write_scope(tmp_path, manifest, "192.168.56.10\n")
    with pytest.raises(TargetOutOfScopeError):
        run_gate(
            manifest_path=manifest_path,
            base_dir=tmp_path,
            workflow="lab_poc",
            environment="lab",
            now=datetime(2026, 1, 1, tzinfo=UTC),
            config={"lab_mode": True},
        )


def test_gate_blocks_when_no_window_open(tmp_path: Path, fixtures: Path) -> None:
    manifest = yaml.safe_load(
        (fixtures / "scope" / "expired_window_manifest.yml").read_text(encoding="utf-8")
    )
    manifest_path = _write_scope(tmp_path, manifest, "192.168.56.10\n")
    with pytest.raises(MaintenanceWindowError):
        run_gate(
            manifest_path=manifest_path,
            base_dir=tmp_path,
            workflow="lab_poc",
            environment="lab",
            now=datetime(2026, 1, 1, tzinfo=UTC),
            config={"lab_mode": True},
        )
