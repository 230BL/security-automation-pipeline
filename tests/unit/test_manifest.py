from __future__ import annotations

from pathlib import Path

import pytest

from src.orchestrator.exceptions import ScopeManifestError
from src.orchestrator.models import ScopeManifest


def test_manifest_loads_valid(fixtures: Path) -> None:
    m = ScopeManifest.from_yaml(fixtures / "scope" / "valid_manifest.yml")
    assert m.assessment_name == "Test Assessment"
    assert len(m.asset_classes) == 1


def test_manifest_missing_fields_raises(fixtures: Path) -> None:
    with pytest.raises(ScopeManifestError):
        ScopeManifest.from_yaml(fixtures / "scope" / "invalid_manifest.yml")
