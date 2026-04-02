"""Time utilities for maintenance window checking and run timing."""

from __future__ import annotations

from datetime import UTC, datetime


def utc_now() -> datetime:
    """Return current UTC time as an aware datetime."""
    return datetime.now(UTC)


def is_within_window(start: datetime, end: datetime, now: datetime | None = None) -> bool:
    """Check if the current time is within the given window."""
    now = now or utc_now()
    return start <= now <= end


def format_duration(seconds: float) -> str:
    """Format a duration in seconds to a human-readable string."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = seconds / 60
    if minutes < 60:
        return f"{minutes:.1f}m"
    hours = minutes / 60
    return f"{hours:.1f}h"
