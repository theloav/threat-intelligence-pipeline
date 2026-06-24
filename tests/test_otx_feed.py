"""Tests for OTXFeed — all HTTP mocked with respx."""
from __future__ import annotations

from datetime import datetime, timedelta
from unittest.mock import MagicMock

import pytest
import respx
import httpx

from tip.core.config import Settings
from tip.core.models import IOCType, ThreatLevel
from tip.feeds.otx_feed import OTXFeed


def _settings(**kwargs) -> Settings:
    defaults = dict(
        misp_api_key="x", otx_api_key="test-key",
        otx_pulse_limit=5, otx_lookback_days=7,
    )
    defaults.update(kwargs)
    return Settings(**defaults)


def _pulse(
    pulse_id="pulse1",
    name="Test Pulse",
    tlp="amber",
    tags=None,
    adversary="APT28",
    indicators=None,
    created=None,
):
    if indicators is None:
        indicators = [
            {"type": "IPv4", "indicator": "1.2.3.4", "description": "C2 server"},
            {"type": "domain", "indicator": "evil.com", "description": ""},
        ]
    if created is None:
        created = datetime.utcnow().isoformat()
    return {
        "id": pulse_id,
        "name": name,
        "TLP": tlp,
        "tags": tags or ["malware"],
        "adversary": adversary,
        "indicators": indicators,
        "created": created,
        "modified": created,
        "references": [],
        "attack_ids": [],
    }


@pytest.mark.asyncio
async def test_fetch_returns_ioc_list():
    """Mocked OTX pulse response yields IOC list."""
    settings = _settings()
    feed = OTXFeed(settings)

    pulse_data = {"results": [_pulse()]}

    with respx.mock:
        respx.get("https://otx.alienvault.com/api/v1/pulses/subscribed").mock(
            return_value=httpx.Response(200, json=pulse_data)
        )
        iocs = await feed.fetch()

    assert len(iocs) >= 2
    values = [i.value for i in iocs]
    assert "1.2.3.4" in values
    assert "evil.com" in values
    await feed.close()


@pytest.mark.asyncio
async def test_indicator_type_mapping():
    """OTX indicator types map correctly to IOCType."""
    settings = _settings()
    feed = OTXFeed(settings)

    indicators = [
        {"type": "IPv4", "indicator": "5.5.5.5"},
        {"type": "IPv6", "indicator": "::1"},
        {"type": "domain", "indicator": "evil.com"},
        {"type": "hostname", "indicator": "host.evil.com"},
        {"type": "URL", "indicator": "http://evil.com/path"},
        {"type": "FileHash-MD5", "indicator": "a" * 32},
        {"type": "FileHash-SHA256", "indicator": "b" * 64},
        {"type": "FileHash-SHA1", "indicator": "c" * 40},
        {"type": "email", "indicator": "bad@evil.com"},
    ]

    pulse_data = {"results": [_pulse(indicators=indicators)]}

    with respx.mock:
        respx.get("https://otx.alienvault.com/api/v1/pulses/subscribed").mock(
            return_value=httpx.Response(200, json=pulse_data)
        )
        iocs = await feed.fetch()

    type_map = {i.value: i.ioc_type for i in iocs}
    assert type_map.get("5.5.5.5") == IOCType.IP
    assert type_map.get("evil.com") == IOCType.DOMAIN
    assert type_map.get("host.evil.com") == IOCType.DOMAIN
    assert type_map.get("http://evil.com/path") == IOCType.URL
    assert type_map.get("a" * 32) == IOCType.MD5
    assert type_map.get("b" * 64) == IOCType.SHA256
    assert type_map.get("c" * 40) == IOCType.SHA1
    assert type_map.get("bad@evil.com") == IOCType.EMAIL
    await feed.close()


@pytest.mark.asyncio
async def test_skip_unknown_indicator_types():
    """Indicator types not in mapping are excluded from results."""
    settings = _settings()
    feed = OTXFeed(settings)

    indicators = [
        {"type": "CIDR", "indicator": "10.0.0.0/8"},        # not mapped
        {"type": "BitcoinAddress", "indicator": "1BvBM..."},  # not mapped
        {"type": "IPv4", "indicator": "8.8.8.8"},             # valid
    ]
    pulse_data = {"results": [_pulse(indicators=indicators)]}

    with respx.mock:
        respx.get("https://otx.alienvault.com/api/v1/pulses/subscribed").mock(
            return_value=httpx.Response(200, json=pulse_data)
        )
        iocs = await feed.fetch()

    values = [i.value for i in iocs]
    assert "8.8.8.8" in values
    assert "10.0.0.0/8" not in values
    assert "1BvBM..." not in values
    await feed.close()


@pytest.mark.asyncio
async def test_health_check_returns_true_on_200():
    settings = _settings()
    feed = OTXFeed(settings)

    with respx.mock:
        respx.get("https://otx.alienvault.com/api/v1/user/me").mock(
            return_value=httpx.Response(200, json={"username": "test"})
        )
        result = await feed.health_check()

    assert result is True
    await feed.close()


@pytest.mark.asyncio
async def test_health_check_returns_false_on_error():
    settings = _settings()
    feed = OTXFeed(settings)

    with respx.mock:
        respx.get("https://otx.alienvault.com/api/v1/user/me").mock(
            return_value=httpx.Response(401, json={"error": "Unauthorized"})
        )
        result = await feed.health_check()

    assert result is False
    await feed.close()


@pytest.mark.asyncio
async def test_lookback_date_is_correct():
    """modified_since param matches settings.otx_lookback_days."""
    settings = _settings(otx_lookback_days=3)
    feed = OTXFeed(settings)

    captured_params = {}

    with respx.mock:
        def capture(request):
            captured_params.update(dict(request.url.params))
            return httpx.Response(200, json={"results": []})

        respx.get("https://otx.alienvault.com/api/v1/pulses/subscribed").mock(side_effect=capture)
        await feed.fetch()

    assert "modified_since" in captured_params
    since_str = captured_params["modified_since"]
    since_dt = datetime.fromisoformat(since_str)
    expected = datetime.utcnow() - timedelta(days=3)
    # Within 2 minutes of expected
    assert abs((since_dt - expected).total_seconds()) < 120
    await feed.close()


@pytest.mark.asyncio
async def test_tlp_maps_to_threat_level():
    """TLP values map to correct ThreatLevel."""
    settings = _settings()
    feed = OTXFeed(settings)

    for tlp, expected_level in [("red", ThreatLevel.HIGH), ("amber", ThreatLevel.MEDIUM), ("green", ThreatLevel.LOW)]:
        pulse_data = {"results": [_pulse(tlp=tlp, indicators=[{"type": "IPv4", "indicator": "1.1.1.1"}])]}
        with respx.mock:
            respx.get("https://otx.alienvault.com/api/v1/pulses/subscribed").mock(
                return_value=httpx.Response(200, json=pulse_data)
            )
            iocs = await feed.fetch()
        if iocs:
            assert iocs[0].threat_level == expected_level, f"TLP {tlp} → {expected_level}"

    await feed.close()
