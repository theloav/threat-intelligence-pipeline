"""Tests for TagWriter — enrichment tag building and SIEM routing."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from tip.core.models import IOC, IOCType, ThreatLevel
from tip.enrichment.tag_writer import TagWriter


def _now():
    return datetime.now(UTC).replace(tzinfo=None)


def _ioc(value="1.2.3.4", ioc_type=IOCType.IP, source_feed="otx", tags=None, attack=None) -> IOC:
    return IOC(
        value=value,
        ioc_type=ioc_type,
        source_feed=source_feed,
        threat_level=ThreatLevel.HIGH,
        tags=tags or [],
        first_seen=_now(),
        last_seen=_now(),
        attack_techniques=attack or [],
    )


def test_build_tags_empty_for_no_matches():
    tw = TagWriter(None, None)
    assert tw.build_enrichment_tags([]) == []


def test_build_tags_always_includes_matched():
    tw = TagWriter(None, None)
    tags = tw.build_enrichment_tags([_ioc()])
    assert "tip:matched" in tags


def test_build_tags_includes_unique_feeds():
    tw = TagWriter(None, None)
    iocs = [
        _ioc(value="1.1.1.1", source_feed="otx"),
        _ioc(value="2.2.2.2", source_feed="threatfox"),
        _ioc(value="3.3.3.3", source_feed="otx"),  # dup feed
    ]
    tags = tw.build_enrichment_tags(iocs)
    assert "tip:feed:otx" in tags
    assert "tip:feed:threatfox" in tags
    assert tags.count("tip:feed:otx") == 1


def test_build_tags_extracts_threat_actor_prefix():
    tw = TagWriter(None, None)
    tags = tw.build_enrichment_tags([_ioc(tags=["threat-actor:APT28"])])
    assert "tip:actor:APT28" in tags


def test_build_tags_detects_known_actor_keywords():
    tw = TagWriter(None, None)
    tags = tw.build_enrichment_tags([_ioc(tags=["lazarus-group"])])
    assert any(t.startswith("tip:actor:") for t in tags)


def test_build_tags_includes_ioc_types():
    tw = TagWriter(None, None)
    iocs = [
        _ioc(value="1.1.1.1", ioc_type=IOCType.IP),
        _ioc(value="evil.com", ioc_type=IOCType.DOMAIN),
    ]
    tags = tw.build_enrichment_tags(iocs)
    assert "tip:ioc-type:ip-dst" in tags
    assert "tip:ioc-type:domain" in tags


def test_build_tags_includes_attack_techniques():
    tw = TagWriter(None, None)
    tags = tw.build_enrichment_tags([_ioc(attack=["T1071", "T1059"])])
    assert "tip:attack:T1071" in tags
    assert "tip:attack:T1059" in tags


@pytest.mark.asyncio
async def test_tag_elastic_alert_calls_update():
    elastic = MagicMock()
    elastic.update_alert = AsyncMock(return_value=True)
    tw = TagWriter(None, elastic)

    result = await tw.tag_elastic_alert("alert-1", ["tip:matched"])

    assert result is True
    elastic.update_alert.assert_awaited_once()
    # Verify the update body structure
    call_args = elastic.update_alert.call_args
    body = call_args[0][1]
    assert body["doc"]["tip.enriched"] is True
    assert body["doc"]["kibana.alert.workflow_tags"] == ["tip:matched"]
    assert "tip.enriched_at" in body["doc"]


@pytest.mark.asyncio
async def test_tag_elastic_returns_false_when_no_client():
    tw = TagWriter(None, None)
    assert await tw.tag_elastic_alert("alert-1", ["x"]) is False


@pytest.mark.asyncio
async def test_tag_sentinel_alert_calls_update_labels():
    sentinel = MagicMock()
    sentinel.update_incident_labels = AsyncMock(return_value=True)
    tw = TagWriter(sentinel, None)

    result = await tw.tag_sentinel_alert("inc-1", ["tip:matched"])

    assert result is True
    sentinel.update_incident_labels.assert_awaited_once_with("inc-1", ["tip:matched"])


@pytest.mark.asyncio
async def test_tag_sentinel_returns_false_when_no_client():
    tw = TagWriter(None, None)
    assert await tw.tag_sentinel_alert("inc-1", ["x"]) is False


@pytest.mark.asyncio
async def test_write_tags_routes_to_elastic():
    elastic = MagicMock()
    elastic.update_alert = AsyncMock(return_value=True)
    tw = TagWriter(None, elastic)

    result = await tw.write_tags("alert-1", "elastic", ["tip:matched"])
    assert result is True
    elastic.update_alert.assert_awaited_once()


@pytest.mark.asyncio
async def test_write_tags_routes_to_sentinel():
    sentinel = MagicMock()
    sentinel.update_incident_labels = AsyncMock(return_value=True)
    tw = TagWriter(sentinel, None)

    result = await tw.write_tags("inc-1", "sentinel", ["tip:matched"])
    assert result is True
    sentinel.update_incident_labels.assert_awaited_once()


@pytest.mark.asyncio
async def test_write_tags_unknown_siem_returns_false():
    tw = TagWriter(None, None)
    assert await tw.write_tags("x", "splunk", ["tip:matched"]) is False
