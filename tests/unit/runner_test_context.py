"""Shared helpers for runner unit tests (no real tools or network)."""

from __future__ import annotations

import shutil
from pathlib import Path

from src.orchestrator.allowlist import Allowlist
from src.orchestrator.gate import GateContext
from src.orchestrator.models import RunMetadata, ScopeManifest


def build_gate_context(
    tmp_path: Path,
    fixtures: Path,
    *,
    run_id: str = "RUN-UNIT-TEST",
    allowlist_lines: str = (
        "192.168.56.10\nhttp://192.168.56.10/\nhttps://example.com/\n10.0.0.1\n10.0.0.2\n10.0.0.3\n"
    ),
    validated_targets: list[str] | None = None,
) -> GateContext:
    """Materialize a minimal scope + allowlist under tmp_path and return GateContext."""
    scope_dir = tmp_path / "scope"
    scope_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy(fixtures / "scope" / "valid_manifest.yml", scope_dir / "scope_manifest.yml")
    (scope_dir / "allowlist.txt").write_text(allowlist_lines, encoding="utf-8")

    manifest = ScopeManifest.from_yaml(scope_dir / "scope_manifest.yml")
    allowlist = Allowlist.from_file(scope_dir / "allowlist.txt")
    targets = validated_targets if validated_targets is not None else ["192.168.56.10"]
    run_metadata = RunMetadata(run_id=run_id, workflow="lab_poc", environment="lab")
    return GateContext(
        manifest=manifest,
        allowlist=allowlist,
        run_metadata=run_metadata,
        scope_hash="",
        allowlist_hash="",
        targets_hash="",
        open_windows=["always_open"],
        validated_targets=targets,
    )
