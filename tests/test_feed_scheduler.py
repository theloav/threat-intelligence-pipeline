"""Tests for FeedScheduler — the dedup/normalise/store orchestration loop."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from tip.core.config import Settings
from tip.core.models import IOC, IOCType, ThreatLevel
from tip.feeds.feed_scheduler import FeedScheduler


def _now():
    return datetime.now(UTC).replace(tzinfo=None)


def _settings() -> Settings:
    return Settings(
        misp_api_key="x",
        otx_api_key="x",
        cache_backend="sqlite",
        cache_sqlite_path=":memory:",
    )


def _ioc(value, ioc_type=IOCType.IP, source_feed="otx") -> IOC:
    return IOC(
        value=value,
        ioc_type=ioc_type,
        source_feed=source_feed,
        threat_level=ThreatLevel.HIGH,
        first_seen=_now(),
        last_seen=_now(),
    )


def _make_scheduler(cache=None, misp=None):
    settings = _settings()
    misp = misp or MagicMock()
    if not hasattr(misp.store_ioc, "_mock_name"):
        misp.store_ioc = AsyncMock(side_effect=lambda ioc: ioc)
    cache = cache or MagicMock()
    return FeedScheduler(settings, misp, cache)


@pytest.mark.asyncio
async def test_run_feed_stores_new_iocs():
    cache = MagicMock()
    cache.exists = AsyncMock(return_value=False)
    cache.add = AsyncMock()
    misp = MagicMock()
    misp.store_ioc = AsyncMock(side_effect=lambda ioc: ioc)

    sched = _make_scheduler(cache=cache, misp=misp)
    feed = MagicMock()
    feed.name = "otx"
    # Public IPs survive normalisation
    feed.fetch = AsyncMock(return_value=[_ioc("8.8.8.8"), _ioc("1.1.1.1")])

    result = await sched._run_feed(feed)

    assert result.new_iocs == 2
    assert result.stored_in_misp == 2
    assert result.duplicate_iocs == 0
    assert result.errors == 0
    assert misp.store_ioc.await_count == 2


@pytest.mark.asyncio
async def test_run_feed_skips_duplicates():
    cache = MagicMock()
    cache.exists = AsyncMock(return_value=True)  # everything is a dupe
    cache.add = AsyncMock()
    misp = MagicMock()
    misp.store_ioc = AsyncMock(side_effect=lambda ioc: ioc)

    sched = _make_scheduler(cache=cache, misp=misp)
    feed = MagicMock()
    feed.name = "otx"
    feed.fetch = AsyncMock(return_value=[_ioc("8.8.8.8")])

    result = await sched._run_feed(feed)

    assert result.duplicate_iocs == 1
    assert result.new_iocs == 0
    assert result.stored_in_misp == 0
    misp.store_ioc.assert_not_awaited()


@pytest.mark.asyncio
async def test_run_feed_normalisation_filters_private_ips():
    cache = MagicMock()
    cache.exists = AsyncMock(return_value=False)
    cache.add = AsyncMock()
    misp = MagicMock()
    misp.store_ioc = AsyncMock(side_effect=lambda ioc: ioc)

    sched = _make_scheduler(cache=cache, misp=misp)
    feed = MagicMock()
    feed.name = "otx"
    # private IP should be dropped by normaliser, only public remains
    feed.fetch = AsyncMock(return_value=[_ioc("192.168.1.1"), _ioc("8.8.8.8")])

    result = await sched._run_feed(feed)

    assert result.total_fetched == 1  # private filtered out before counting
    assert result.stored_in_misp == 1


@pytest.mark.asyncio
async def test_run_feed_counts_store_errors():
    cache = MagicMock()
    cache.exists = AsyncMock(return_value=False)
    cache.add = AsyncMock()
    misp = MagicMock()
    misp.store_ioc = AsyncMock(side_effect=RuntimeError("MISP down"))

    sched = _make_scheduler(cache=cache, misp=misp)
    feed = MagicMock()
    feed.name = "otx"
    feed.fetch = AsyncMock(return_value=[_ioc("8.8.8.8")])

    result = await sched._run_feed(feed)

    assert result.errors == 1
    assert result.stored_in_misp == 0
    assert result.error_details


@pytest.mark.asyncio
async def test_run_feed_handles_fetch_exception():
    sched = _make_scheduler()
    feed = MagicMock()
    feed.name = "otx"
    feed.fetch = AsyncMock(side_effect=ConnectionError("network unreachable"))

    result = await sched._run_feed(feed)

    assert result.errors == 1
    assert result.total_fetched == 0
    assert "network unreachable" in result.error_details[0]


@pytest.mark.asyncio
async def test_run_once_all_runs_both_feeds():
    sched = _make_scheduler()
    sched._run_feed = AsyncMock(side_effect=lambda feed: MagicMock(feed_name=feed.name))
    results = await sched.run_once("all")
    assert len(results) == 2


@pytest.mark.asyncio
async def test_run_once_single_feed():
    sched = _make_scheduler()
    sched._run_feed = AsyncMock(side_effect=lambda feed: MagicMock(feed_name=feed.name))
    results = await sched.run_once("otx")
    assert len(results) == 1


def test_get_last_results_returns_copy():
    sched = _make_scheduler()
    sched._last_results = {"otx": "placeholder"}
    snap = sched.get_last_results()
    snap["abusech"] = "x"
    # original not mutated
    assert "abusech" not in sched._last_results
