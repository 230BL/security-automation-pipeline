from __future__ import annotations

from pathlib import Path

import pytest


def fixture_path(*parts: str) -> Path:
    return Path(__file__).parent / "fixtures" / Path(*parts)


def pytest_configure() -> None:
    # Ensure project root is importable when running tests without installation.
    import sys

    root = Path(__file__).resolve().parent.parent
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))


@pytest.fixture
def fixtures() -> Path:
    return Path(__file__).parent / "fixtures"
