"""Orchestrator entry points.

This module wires the governance gate to runner execution.
The user-facing CLI is implemented in `scripts/run_pipeline.py`.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from src.orchestrator.gate import GateContext, run_gate
from src.utils.logging_setup import setup_logging

LOG = logging.getLogger(__name__)


def load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def gate_only(
    manifest_path: Path = Path("scope/scope_manifest.yml"),
    workflow: str = "lab_poc",
    environment: str = "lab",
    base_dir: Path = Path("."),
) -> GateContext:
    """Run the authorization gate and return the validated context."""
    ctx = run_gate(
        manifest_path=manifest_path,
        base_dir=base_dir,
        workflow=workflow,
        environment=environment,
    )
    setup_logging(ctx.run_metadata.run_id)
    LOG.info("Gate-only run succeeded for %s", ctx.run_metadata.run_id)
    return ctx
