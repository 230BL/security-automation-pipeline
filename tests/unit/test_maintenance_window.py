from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from src.orchestrator.exceptions import MaintenanceWindowError
from src.orchestrator.maintenance_window import validate_window
from src.orchestrator.models import ScopeManifest


def test_validate_window_open(fixtures: Path) -> None:
    manifest = ScopeManifest.from_yaml(fixtures / "scope" / "valid_manifest.yml")
    now = datetime(2026, 1, 1, tzinfo=UTC)
    assert validate_window(manifest, "always_open", now=now) is True


def test_validate_window_missing_raises(fixtures: Path) -> None:
    manifest = ScopeManifest.from_yaml(fixtures / "scope" / "valid_manifest.yml")
    with pytest.raises(MaintenanceWindowError):
        validate_window(manifest, "nope", now=datetime.now(UTC))
