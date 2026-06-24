"""Tests for AbuseCHFeed — mocked with respx."""

from __future__ import annotations

import httpx
import pytest
import respx

from tip.core.config import Settings
from tip.core.models import IOCType, ThreatLevel
from tip.feeds.abusech_feed import AbuseCHFeed


def _settings(auth_key: str = "") -> Settings:
    return Settings(misp_api_key="x", otx_api_key="x", abusech_auth_key=auth_key)


def _malware_response():
    return {
        "query_status": "ok",
        "data": [
            {
                "sha256_hash": "a" * 64,
                "md5_hash": "b" * 32,
                "file_name": "evil.exe",
                "signature": "Emotet",
                "file_type": "exe",
                "tags": ["emotet", "banking"],
                "first_seen": "2024-01-15 10:00:00",
                "last_seen": "2024-01-15 10:00:00",
            }
        ],
    }


def _urlhaus_response():
    return {
        "urls": [
            {
                "id": "123",
                "url": "http://malicious.example.com/payload",
                "host": "malicious.example.com",
                "threat": "malware_download",
                "tags": ["malware"],
                "date_added": "2024-01-15 10:00:00",
            }
        ]
    }


def _threatfox_response():
    return {
        "query_status": "ok",
        "data": [
            {
                "id": "456",
                "ioc": "192.168.1.100:4444",
                "ioc_type": "ip:port",
                "malware": "CobaltStrike",
                "malware_alias": "CS",
                "confidence_level": 80,
                "tags": ["cobalt-strike"],
                "first_seen": "2024-01-15 10:00:00",
                "last_seen": "2024-01-15 10:00:00",
            },
            {
                "id": "457",
                "ioc": "1.2.3.4:443",
                "ioc_type": "ip:port",
                "malware": "Sliver",
                "malware_alias": "",
                "confidence_level": 55,
                "tags": [],
                "first_seen": "2024-01-15 10:00:00",
            },
            {
                "id": "458",
                "ioc": "1.2.3.5:80",
                "ioc_type": "ip:port",
                "malware": "Loader",
                "malware_alias": "",
                "confidence_level": 30,
                "tags": [],
                "first_seen": "2024-01-15 10:00:00",
            },
        ],
    }


def _mock_all(mock_router):
    mock_router.post("https://mb-api.abuse.ch/api/v1/").mock(
        return_value=httpx.Response(200, json=_malware_response())
    )
    mock_router.post("https://urlhaus-api.abuse.ch/v1/urls/recent/").mock(
        return_value=httpx.Response(200, json=_urlhaus_response())
    )
    mock_router.post("https://threatfox-api.abuse.ch/api/v1/").mock(
        return_value=httpx.Response(200, json=_threatfox_response())
    )


@pytest.mark.asyncio
async def test_fetch_combines_all_sources():
    """fetch() returns IOCs from all three Abuse.ch sources combined."""
    feed = AbuseCHFeed(_settings())
    with respx.mock:
        _mock_all(respx)
        iocs = await feed.fetch()

    assert len(iocs) > 3  # sha256 + md5 + filename + url + host + multiple ThreatFox
    sources = {ioc.source_feed for ioc in iocs}
    assert "abusech_malware" in sources
    assert "abusech_url" in sources
    assert "threatfox" in sources
    await feed.close()


@pytest.mark.asyncio
async def test_malwarebazaar_creates_sha256_ioc():
    feed = AbuseCHFeed(_settings())
    with respx.mock:
        _mock_all(respx)
        iocs = await feed.fetch()

    sha256_iocs = [i for i in iocs if i.ioc_type == IOCType.SHA256]
    assert len(sha256_iocs) >= 1
    assert sha256_iocs[0].value == "a" * 64
    assert sha256_iocs[0].source_feed == "abusech_malware"
    assert sha256_iocs[0].threat_level == ThreatLevel.HIGH
    assert "Emotet" in sha256_iocs[0].tags
    await feed.close()


@pytest.mark.asyncio
async def test_urlhaus_creates_url_and_domain_iocs():
    feed = AbuseCHFeed(_settings())
    with respx.mock:
        _mock_all(respx)
        iocs = await feed.fetch()

    url_iocs = [i for i in iocs if i.ioc_type == IOCType.URL and i.source_feed == "abusech_url"]
    domain_iocs = [
        i for i in iocs if i.ioc_type == IOCType.DOMAIN and i.source_feed == "abusech_url"
    ]

    assert len(url_iocs) >= 1
    assert "http://malicious.example.com/payload" in [i.value for i in url_iocs]
    assert len(domain_iocs) >= 1
    assert "malicious.example.com" in [i.value for i in domain_iocs]
    await feed.close()


@pytest.mark.asyncio
async def test_threatfox_ip_port_extracts_ip():
    """'1.2.3.4:443' in ThreatFox → ip-dst IOC with value '1.2.3.4'."""
    feed = AbuseCHFeed(_settings())
    with respx.mock:
        _mock_all(respx)
        iocs = await feed.fetch()

    tf_ip_iocs = [i for i in iocs if i.source_feed == "threatfox" and i.ioc_type == IOCType.IP]
    values = [i.value for i in tf_ip_iocs]
    assert "1.2.3.4" in values
    # Should NOT include port number
    assert "1.2.3.4:443" not in values
    await feed.close()


@pytest.mark.asyncio
async def test_threatfox_confidence_maps_to_threat_level():
    """80 → high, 55 → medium, 30 → low."""
    feed = AbuseCHFeed(_settings())
    with respx.mock:
        _mock_all(respx)
        iocs = await feed.fetch()

    tf_iocs = {
        i.value: i for i in iocs if i.source_feed == "threatfox" and i.ioc_type == IOCType.IP
    }

    # confidence 80 → HIGH
    assert (
        tf_iocs.get("192.168.1.100") and tf_iocs["192.168.1.100"].threat_level == ThreatLevel.HIGH
    )
    # confidence 55 → MEDIUM
    assert tf_iocs.get("1.2.3.4") and tf_iocs["1.2.3.4"].threat_level == ThreatLevel.MEDIUM
    # confidence 30 → LOW
    assert tf_iocs.get("1.2.3.5") and tf_iocs["1.2.3.5"].threat_level == ThreatLevel.LOW
    await feed.close()


@pytest.mark.asyncio
async def test_health_check_returns_true():
    feed = AbuseCHFeed(_settings())
    with respx.mock:
        respx.post("https://mb-api.abuse.ch/api/v1/").mock(
            return_value=httpx.Response(200, json={"query_status": "no_results"})
        )
        result = await feed.health_check()
    assert result is True
    await feed.close()


@pytest.mark.asyncio
async def test_partial_source_failure_still_returns_others():
    """If URLhaus fails, still returns MalwareBazaar + ThreatFox IOCs."""
    feed = AbuseCHFeed(_settings())
    with respx.mock:
        respx.post("https://mb-api.abuse.ch/api/v1/").mock(
            return_value=httpx.Response(200, json=_malware_response())
        )
        respx.post("https://urlhaus-api.abuse.ch/v1/urls/recent/").mock(
            side_effect=httpx.ConnectError("timeout")
        )
        respx.post("https://threatfox-api.abuse.ch/api/v1/").mock(
            return_value=httpx.Response(200, json=_threatfox_response())
        )
        iocs = await feed.fetch()

    sources = {i.source_feed for i in iocs}
    assert "abusech_malware" in sources
    assert "threatfox" in sources
    await feed.close()


def test_auth_key_sent_as_header_when_configured():
    """Abuse.ch Auth-Key (required since 2024) is attached to requests."""
    feed = AbuseCHFeed(_settings(auth_key="secret-key-123"))
    assert feed.client.headers.get("Auth-Key") == "secret-key-123"


def test_no_auth_header_when_key_absent():
    feed = AbuseCHFeed(_settings(auth_key=""))
    assert "Auth-Key" not in feed.client.headers


@pytest.mark.asyncio
async def test_health_check_401_returns_false():
    """A 401 (missing Auth-Key) is reachable-but-unauthorised → False."""
    feed = AbuseCHFeed(_settings())
    with respx.mock:
        respx.post("https://mb-api.abuse.ch/api/v1/").mock(
            return_value=httpx.Response(401, json={"error": "Unauthorized"})
        )
        result = await feed.health_check()
    assert result is False
    await feed.close()
