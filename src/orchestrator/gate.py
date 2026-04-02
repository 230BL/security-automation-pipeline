"""Authorization gate - the single entry point for all execution prerequisites.

All checks must pass or execution is blocked. No partial passes.
No silent fallbacks. Every failure raises a specific exception.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from src.orchestrator.allowlist import Allowlist
from src.orchestrator.exceptions import (
    EnvironmentMismatchError,
    MaintenanceWindowError,
    ScopeSignatureError,
    TargetOutOfScopeError,
    WorkflowNotApprovedError,
)
from src.orchestrator.maintenance_window import validate_any_window_open
from src.orchestrator.manifest import load_manifest, verify_scope_pdf_hash
from src.orchestrator.models import RunMetadata, ScopeManifest
from src.orchestrator.scope import verify_scope_lab_mode, verify_scope_signature
from src.utils.hashing import hash_file, hash_targets

LOG = logging.getLogger(__name__)


@dataclass
class GateContext:
    """Validated context returned by the authorization gate."""

    manifest: ScopeManifest
    allowlist: Allowlist
    run_metadata: RunMetadata
    scope_hash: str
    allowlist_hash: str
    targets_hash: str
    open_windows: list[str]
    validated_targets: list[str]


def load_gate_config(config_path: Path = Path("config/orchestrator.yml")) -> dict[str, Any]:
    """Load orchestrator configuration."""
    if not config_path.exists():
        LOG.warning("Orchestrator config not found at %s, using defaults", config_path)
        return {}
    return yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}


def run_gate(
    manifest_path: Path = Path("scope/scope_manifest.yml"),
    base_dir: Path = Path("."),
    workflow: str = "weekly_defensive_validation",
    environment: str = "nonprod",
    executor: str = "",
    now: datetime | None = None,
    config: dict[str, Any] | None = None,
) -> GateContext:
    """Execute all authorization checks. All must pass or execution is blocked."""
    config = config or load_gate_config()
    now = now or datetime.now(UTC)
    lab_mode = bool(config.get("lab_mode", False))

    LOG.info("=== AUTHORIZATION GATE START ===")

    # 1. Scope signature verification
    LOG.info("Check 1/7: Scope signature verification")
    if lab_mode:
        verify_scope_lab_mode(manifest_path, lab_mode_enabled=True)
    else:
        sig_path = manifest_path.with_suffix(manifest_path.suffix + ".sig")
        keyring_path = base_dir / "scope" / "approved_signers.gpg"
        verify_scope_signature(manifest_path, sig_path, keyring_path)

    # 2. Load and validate manifest
    LOG.info("Check 2/7: Manifest loading and validation")
    manifest = load_manifest(manifest_path)

    # 3. Verify scope PDF hash (skip in lab mode if PDF doesn't exist)
    LOG.info("Check 3/7: Scope PDF hash verification")
    pdf_path = base_dir / manifest.authorization.signed_scope_pdf
    if pdf_path.exists():
        verify_scope_pdf_hash(manifest, base_dir)
    elif not lab_mode:
        raise ScopeSignatureError(f"Signed scope PDF not found: {pdf_path}")
    else:
        LOG.warning("Signed scope PDF not found - acceptable in lab mode only")

    # 4. Load and enforce allowlist
    LOG.info("Check 4/7: Allowlist loading and target enforcement")
    allowlist_path = base_dir / manifest.allowlist_file
    allowlist = Allowlist.from_file(allowlist_path)
    all_targets = manifest.all_targets()

    if len(all_targets) > manifest.max_target_count:
        raise TargetOutOfScopeError(
            set(),
            message=(
                f"Target count {len(all_targets)} exceeds manifest ceiling "
                f"{manifest.max_target_count}"
            ),
        )

    allowlist.enforce(all_targets)

    exclusions = {e.lower() for e in manifest.all_exclusions()}
    for target in all_targets:
        if target.lower() in exclusions:
            raise TargetOutOfScopeError(
                {target}, message=f"Target {target} is in the exclusion list"
            )

    # 5. Maintenance window check
    LOG.info("Check 5/7: Maintenance window validation")
    open_windows = validate_any_window_open(manifest, now)
    if not open_windows:
        raise MaintenanceWindowError(
            f"No maintenance windows are currently open. Current time: {now.isoformat()}"
        )

    # 6. Workflow approval
    LOG.info("Check 6/7: Workflow approval check")
    if workflow not in manifest.approved_workflows:
        raise WorkflowNotApprovedError(
            f"Workflow '{workflow}' is not approved. Approved workflows: "
            f"{manifest.approved_workflows}"
        )

    # 7. Environment validation
    LOG.info("Check 7/7: Environment label validation")
    valid_environments = {ac.environment for ac in manifest.asset_classes}
    if environment not in valid_environments and environment not in ("nonprod", "lab", "staging"):
        raise EnvironmentMismatchError(
            f"Environment '{environment}' is not valid for this scope. "
            f"Valid environments: {sorted(valid_environments)}"
        )

    scope_hash = hash_file(manifest_path)
    allowlist_hash = hash_file(allowlist_path)
    targets_hash = hash_targets(all_targets)

    run_meta = RunMetadata(
        scope_hash=scope_hash,
        allowlist_hash=allowlist_hash,
        workflow=workflow,
        environment=environment,
        executor=executor or os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
    )

    ctx = GateContext(
        manifest=manifest,
        allowlist=allowlist,
        run_metadata=run_meta,
        scope_hash=scope_hash,
        allowlist_hash=allowlist_hash,
        targets_hash=targets_hash,
        open_windows=open_windows,
        validated_targets=all_targets,
    )

    LOG.info(
        "=== AUTHORIZATION GATE PASSED === run_id=%s scope_hash=%s targets=%d",
        run_meta.run_id,
        scope_hash[:16] + "...",
        len(all_targets),
    )
    return ctx
