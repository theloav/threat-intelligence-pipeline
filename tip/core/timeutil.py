"""
Time helpers.

The whole pipeline works with **naive UTC** datetimes (no tzinfo) so that
comparisons against values parsed from feed/SIEM APIs — which are frequently
naive — never raise ``TypeError: can't compare offset-naive and offset-aware``.

``datetime.utcnow()`` is deprecated from Python 3.12 onward, so we centralise the
replacement here: ``datetime.now(timezone.utc)`` (correct, non-deprecated) with
the tzinfo stripped to keep values naive-UTC.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta


def utcnow() -> datetime:
    """Return the current UTC time as a naive datetime."""
    return datetime.now(UTC).replace(tzinfo=None)


def utc_days_ago(days: int) -> datetime:
    """Return naive-UTC datetime ``days`` days in the past."""
    return utcnow() - timedelta(days=days)


def utc_minutes_ago(minutes: int) -> datetime:
    """Return naive-UTC datetime ``minutes`` minutes in the past."""
    return utcnow() - timedelta(minutes=minutes)


def ensure_naive_utc(dt: datetime) -> datetime:
    """Coerce a possibly tz-aware datetime to naive UTC."""
    if dt.tzinfo is not None:
        return dt.astimezone(UTC).replace(tzinfo=None)
    return dt
