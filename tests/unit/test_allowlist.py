from __future__ import annotations

from pathlib import Path

import pytest

from src.orchestrator.allowlist import Allowlist
from src.orchestrator.exceptions import TargetOutOfScopeError


def test_allowlist_enforces_subset(fixtures: Path) -> None:
    al = Allowlist.from_file(fixtures / "scope" / "valid_allowlist.txt")
    al.enforce(["192.168.56.10"])


def test_allowlist_out_of_scope_raises(fixtures: Path) -> None:
    al = Allowlist.from_file(fixtures / "scope" / "valid_allowlist.txt")
    with pytest.raises(TargetOutOfScopeError) as exc:
        al.enforce(["10.0.0.99"])
    assert "10.0.0.99" in str(exc.value)
