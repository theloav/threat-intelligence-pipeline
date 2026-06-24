"""Tests for MISPLookup — mocks PyMISP and MISPClient."""
from __future__ import annotations

from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tip.core.models import IOCType
from tip.enrichment.misp_lookup import MISPLookup


def _make_lookup():
    """Create MISPLookup with fully mocked MISPClient."""
    misp_client = MagicMock()
    misp_client.get_ioc_context = AsyncMock(return_value={
        "matched": False, "attributes": [], "events": [],
        "tags": [], "threat_actors": [], "campaigns": [], "feeds": [],
    })
    misp_client.lookup_many = AsyncMock(return_value={})
    return MISPLookup(misp_client), misp_client


@pytest.mark.asyncio
async def test_lookup_matched_ioc_returns_context():
    lookup, misp_client = _make_lookup()

    misp_client.get_ioc_context = AsyncMock(return_value={
        "matched": True,
        "attributes": [
            {
                "id": "1", "type": "ip-dst", "value": "1.2.3.4",
                "comment": "C2 server", "event_id": "10",
                "Tag": [{"name": "threat-actor:APT28"}],
                "Event": {"id": "10", "info": "otx — 2024-01-15"},
            }
        ],
        "events": [{"id": "10", "info": "otx — 2024-01-15"}],
        "tags": ["threat-actor:APT28"],
        "threat_actors": ["APT28"],
        "campaigns": [],
        "feeds": ["otx"],
    })

    result = await lookup.lookup_ioc("1.2.3.4")
    assert result["matched"] is True
    assert result["ioc"] is not None
    assert result["ioc"].value == "1.2.3.4"
    assert result["context"]["threat_actors"] == ["APT28"]


@pytest.mark.asyncio
async def test_lookup_no_match_returns_empty():
    lookup, _ = _make_lookup()

    result = await lookup.lookup_ioc("not-in-misp.com")
    assert result["matched"] is False
    assert result["ioc"] is None
    assert result["context"]["attributes"] == []


@pytest.mark.asyncio
async def test_extract_iocs_from_elastic_alert():
    lookup, _ = _make_lookup()

    elastic_alert = {
        "_id": "alert-123",
        "_source": {
            "source.ip": "1.2.3.4",
            "destination.ip": "5.6.7.8",
            "dns.question.name": "evil-domain.com",
            "url.full": "http://evil-domain.com/payload",
            "process.hash.sha256": "a" * 64,
            "@timestamp": "2024-01-15T10:00:00Z",
        },
    }

    extracted = lookup.extract_iocs_from_alert(elastic_alert, "elastic")

    assert "1.2.3.4" in extracted
    assert "5.6.7.8" in extracted
    assert "evil-domain.com" in extracted


@pytest.mark.asyncio
async def test_extract_iocs_from_sentinel_alert():
    lookup, _ = _make_lookup()

    sentinel_alert = {
        "name": "/subscriptions/xxx/incidents/1",
        "properties": {
            "title": "Suspicious IP Connection",
            "severity": "High",
            "createdTimeUtc": "2024-01-15T10:00:00Z",
            "entities": [
                {"address": "10.10.10.10"},  # private — should be filtered
                {"address": "185.220.101.5"},  # public
                {"domainName": "malicious.example.com"},
                {"fileHashes": [{"hashValue": "b" * 64}]},
                {"url": "http://c2.example.com/beacon"},
            ],
        },
    }

    extracted = lookup.extract_iocs_from_alert(sentinel_alert, "sentinel")

    assert "185.220.101.5" in extracted
    assert "malicious.example.com" in extracted
    assert "b" * 64 in extracted
    # Private IP should be filtered
    assert "10.10.10.10" not in extracted


@pytest.mark.asyncio
async def test_private_ip_not_extracted():
    """Private IPs in alert should not appear in extracted list."""
    lookup, _ = _make_lookup()

    alert = {
        "_source": {
            "source.ip": "10.0.0.1",
            "destination.ip": "192.168.1.100",
            "host.ip": "172.16.0.5",
        }
    }

    extracted = lookup.extract_iocs_from_alert(alert, "elastic")
    for private in ["10.0.0.1", "192.168.1.100", "172.16.0.5"]:
        assert private not in extracted


@pytest.mark.asyncio
async def test_lookup_alert_iocs_returns_matched():
    lookup, misp_client = _make_lookup()

    misp_client.lookup_many = AsyncMock(return_value={
        "5.5.5.5": [
            {
                "id": "2", "type": "ip-dst", "value": "5.5.5.5",
                "comment": "Known C2", "event_id": "20",
                "Tag": [], "Event": {"id": "20", "info": "otx — 2024-01-15"},
            }
        ],
        "8.8.8.8": [],  # no match
    })
    misp_client.get_ioc_context = AsyncMock(return_value={
        "matched": True, "attributes": [], "events": [], "tags": [],
        "threat_actors": [], "campaigns": [], "feeds": [],
    })

    matched = await lookup.lookup_alert_iocs(["5.5.5.5", "8.8.8.8"])
    assert len(matched) == 1
    assert matched[0].value == "5.5.5.5"
