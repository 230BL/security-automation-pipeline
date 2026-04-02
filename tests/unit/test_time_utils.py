from __future__ import annotations

from datetime import UTC, datetime, timedelta

from src.utils import time_utils


def test_utc_now_returns_aware_utc_datetime() -> None:
    now = time_utils.utc_now()

    assert now.tzinfo is UTC


def test_is_within_window_true_when_now_inside_explicit_window() -> None:
    now = datetime(2026, 3, 31, 10, 0, tzinfo=UTC)
    start = now - timedelta(minutes=5)
    end = now + timedelta(minutes=5)

    assert time_utils.is_within_window(start, end, now=now) is True


def test_is_within_window_false_when_now_before_window() -> None:
    now = datetime(2026, 3, 31, 10, 0, tzinfo=UTC)
    start = now + timedelta(minutes=1)
    end = now + timedelta(minutes=10)

    assert time_utils.is_within_window(start, end, now=now) is False


def test_is_within_window_false_when_now_after_window() -> None:
    now = datetime(2026, 3, 31, 10, 0, tzinfo=UTC)
    start = now - timedelta(minutes=10)
    end = now - timedelta(minutes=1)

    assert time_utils.is_within_window(start, end, now=now) is False


def test_is_within_window_uses_utc_now_when_now_not_supplied(
    monkeypatch,
) -> None:
    fake_now = datetime(2026, 3, 31, 12, 0, tzinfo=UTC)

    monkeypatch.setattr(time_utils, "utc_now", lambda: fake_now)

    start = fake_now - timedelta(seconds=1)
    end = fake_now + timedelta(seconds=1)

    assert time_utils.is_within_window(start, end) is True


def test_format_duration_seconds() -> None:
    assert time_utils.format_duration(12.34) == "12.3s"


def test_format_duration_minutes() -> None:
    assert time_utils.format_duration(120) == "2.0m"


def test_format_duration_hours() -> None:
    assert time_utils.format_duration(7200) == "2.0h"


def test_format_duration_boundary_at_60_seconds_is_minutes() -> None:
    assert time_utils.format_duration(60) == "1.0m"


def test_format_duration_boundary_at_60_minutes_is_hours() -> None:
    assert time_utils.format_duration(3600) == "1.0h"
