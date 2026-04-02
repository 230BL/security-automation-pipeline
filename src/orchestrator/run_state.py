"""Run state persistence for crash recovery and resumability.

Each run gets a JSON state file in evidence/state/ that tracks
phase completion. If the orchestrator crashes, it can resume
from the last completed phase.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from src.orchestrator.exceptions import RunStateError

LOG = logging.getLogger(__name__)


class RunState:
    """Persistent state tracker for a pipeline run."""

    def __init__(self, run_id: str, state_dir: Path = Path("evidence/state")):
        self.run_id = run_id
        self.state_dir = state_dir
        self.state_file = state_dir / f"{run_id}.json"
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self._state = self._load()

    def _load(self) -> dict[str, Any]:
        if self.state_file.exists():
            try:
                data = json.loads(self.state_file.read_text(encoding="utf-8"))
                if not isinstance(data, dict):
                    raise RunStateError(f"State file is not a JSON object: {self.state_file}")
                LOG.info("Loaded existing run state for %s", self.run_id)
                return data
            except json.JSONDecodeError as exc:
                raise RunStateError(f"State file is corrupted: {self.state_file}: {exc}") from exc
        return {"run_id": self.run_id, "created": datetime.now(UTC).isoformat(), "phases": {}}

    def _save(self) -> None:
        self._state["updated"] = datetime.now(UTC).isoformat()
        self.state_file.write_text(json.dumps(self._state, indent=2, default=str), encoding="utf-8")

    def mark_started(self, phase: str) -> None:
        self._state["phases"][phase] = {
            "status": "running",
            "started": datetime.now(UTC).isoformat(),
        }
        self._save()
        LOG.info("Phase '%s' started", phase)

    def mark_complete(self, phase: str, artifacts: list[str] | None = None) -> None:
        phase_data = self._state["phases"].get(phase, {})
        phase_data.update(
            {
                "status": "complete",
                "completed": datetime.now(UTC).isoformat(),
                "artifacts": artifacts or [],
            }
        )
        self._state["phases"][phase] = phase_data
        self._save()
        LOG.info("Phase '%s' completed with %d artifacts", phase, len(artifacts or []))

    def mark_failed(self, phase: str, error: str) -> None:
        phase_data = self._state["phases"].get(phase, {})
        phase_data.update(
            {
                "status": "failed",
                "failed": datetime.now(UTC).isoformat(),
                "error": error,
            }
        )
        self._state["phases"][phase] = phase_data
        self._save()
        LOG.error("Phase '%s' failed: %s", phase, error)

    def mark_skipped(self, phase: str, reason: str) -> None:
        self._state["phases"][phase] = {
            "status": "skipped",
            "timestamp": datetime.now(UTC).isoformat(),
            "reason": reason,
        }
        self._save()
        LOG.info("Phase '%s' skipped: %s", phase, reason)

    def is_complete(self, phase: str) -> bool:
        phases = cast(dict[str, dict[str, Any]], self._state.get("phases", {}))
        return phases.get(phase, {}).get("status") == "complete"

    def is_failed(self, phase: str) -> bool:
        phases = cast(dict[str, dict[str, Any]], self._state.get("phases", {}))
        return phases.get(phase, {}).get("status") == "failed"

    def get_status(self, phase: str) -> str:
        phases = cast(dict[str, dict[str, Any]], self._state.get("phases", {}))
        status = phases.get(phase, {}).get("status")
        return str(status) if status is not None else "not_started"

    def get_completed_phases(self) -> list[str]:
        phases = cast(dict[str, dict[str, Any]], self._state.get("phases", {}))
        return [name for name, data in phases.items() if data.get("status") == "complete"]

    def get_artifacts(self, phase: str) -> list[str]:
        phases = cast(dict[str, dict[str, Any]], self._state.get("phases", {}))
        artifacts = phases.get(phase, {}).get("artifacts", [])
        if isinstance(artifacts, list):
            return [str(a) for a in artifacts]
        return []

    def to_dict(self) -> dict[str, Any]:
        return dict(self._state)
