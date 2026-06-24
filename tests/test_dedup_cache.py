"""Tests for DedupCache — uses in-memory SQLite for isolation."""
from __future__ import annotations

import asyncio
from datetime import timedelta
from unittest.mock import patch, MagicMock

import pytest

from tip.core.models import IOCType


def _make_cache(ttl_days=30):
    """Create a DedupCache backed by in-memory SQLite."""
    from tip.core.config import Settings
    from tip.misp.dedup_cache import DedupCache
    settings = Settings(
        misp_api_key="x",
        cache_backend="sqlite",
        cache_sqlite_path=":memory:",
        cache_ttl_days=ttl_days,
    )
    return DedupCache(settings)


@pytest.mark.asyncio
async def test_new_ioc_not_in_cache():
    cache = _make_cache()
    result = await cache.exists("8.8.8.8", IOCType.IP)
    assert result is False


@pytest.mark.asyncio
async def test_add_then_exists_returns_true():
    cache = _make_cache()
    await cache.add("evil.com", IOCType.DOMAIN)
    result = await cache.exists("evil.com", IOCType.DOMAIN)
    assert result is True


@pytest.mark.asyncio
async def test_different_type_not_matched():
    """Same value with different IOC type is a separate cache entry."""
    cache = _make_cache()
    await cache.add("evil.com", IOCType.DOMAIN)
    # Looking up as URL should not match
    result = await cache.exists("evil.com", IOCType.URL)
    assert result is False


@pytest.mark.asyncio
async def test_expired_entry_not_found():
    """Entry added with ttl=0 days should not be found (already expired)."""
    import sqlite3
    from datetime import datetime

    cache = _make_cache(ttl_days=0)
    # Manually insert with past expiry
    with cache._get_conn() as conn:
        past = (datetime.utcnow() - timedelta(seconds=1)).isoformat()
        conn.execute(
            "INSERT OR REPLACE INTO ioc_cache (value, ioc_type, first_seen, expires) VALUES (?, ?, ?, ?)",
            ("stale.com", IOCType.DOMAIN.value, datetime.utcnow().isoformat(), past),
        )

    result = await cache.exists("stale.com", IOCType.DOMAIN)
    assert result is False


@pytest.mark.asyncio
async def test_stats_returns_correct_count():
    cache = _make_cache()
    await cache.add("8.8.8.8", IOCType.IP)
    await cache.add("evil.com", IOCType.DOMAIN)
    await cache.add("badfile.exe", IOCType.FILENAME)

    stats = await cache.stats()
    assert stats["total_entries"] == 3
    assert stats["backend"] == "sqlite"
    assert stats["ttl_days"] == 30


@pytest.mark.asyncio
async def test_remove_deletes_entry():
    cache = _make_cache()
    await cache.add("evil.com", IOCType.DOMAIN)
    assert await cache.exists("evil.com", IOCType.DOMAIN) is True
    await cache.remove("evil.com", IOCType.DOMAIN)
    assert await cache.exists("evil.com", IOCType.DOMAIN) is False


@pytest.mark.asyncio
async def test_purge_expired_removes_old_entries():
    import sqlite3
    from datetime import datetime

    cache = _make_cache()
    # Add a valid entry
    await cache.add("good.com", IOCType.DOMAIN)
    # Add an expired entry directly
    with cache._get_conn() as conn:
        past = (datetime.utcnow() - timedelta(seconds=1)).isoformat()
        conn.execute(
            "INSERT OR REPLACE INTO ioc_cache (value, ioc_type, first_seen, expires) VALUES (?, ?, ?, ?)",
            ("expired.com", IOCType.DOMAIN.value, datetime.utcnow().isoformat(), past),
        )

    count = await cache.purge_expired()
    assert count >= 1
    # Valid entry still exists
    assert await cache.exists("good.com", IOCType.DOMAIN) is True
    # Expired entry gone
    assert await cache.exists("expired.com", IOCType.DOMAIN) is False


@pytest.mark.asyncio
async def test_stats_by_type_breakdown():
    cache = _make_cache()
    await cache.add("1.1.1.1", IOCType.IP)
    await cache.add("2.2.2.2", IOCType.IP)
    await cache.add("evil.com", IOCType.DOMAIN)

    stats = await cache.stats()
    by_type = stats.get("by_type", {})
    assert by_type.get("ip-dst") == 2
    assert by_type.get("domain") == 1
