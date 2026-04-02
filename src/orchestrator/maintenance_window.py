"""Maintenance window validation.

Checks that the current time falls within an approved maintenance window
for the requested asset class.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from src.orchestrator.exceptions import MaintenanceWindowError
from src.orchestrator.models import ScopeManifest

LOG = logging.getLogger(__name__)


def validate_window(
    manifest: ScopeManifest,
    window_name: str,
    now: datetime | None = None,
) -> bool:
    """Check that the named maintenance window is currently open."""
    now = now or datetime.now(UTC)
    window = manifest.get_window(window_name)

    if window is None:
        raise MaintenanceWindowError(
            f"Maintenance window '{window_name}' not found in scope manifest"
        )

    if not window.is_open(now):
        raise MaintenanceWindowError(
            f"Maintenance window '{window_name}' is not open. "
            f"Window: {window.start.isoformat()} to {window.end.isoformat()}, "
            f"Current time: {now.isoformat()}"
        )

    LOG.info("Maintenance window '%s' is open (closes %s)", window_name, window.end.isoformat())
    return True


def validate_any_window_open(
    manifest: ScopeManifest,
    now: datetime | None = None,
) -> list[str]:
    """Return list of currently open maintenance window names."""
    now = now or datetime.now(UTC)
    open_windows: list[str] = []
    for window in manifest.maintenance_windows:
        if window.is_open(now):
            open_windows.append(window.name)

    if not open_windows:
        LOG.warning("No maintenance windows are currently open")

    return open_windows
