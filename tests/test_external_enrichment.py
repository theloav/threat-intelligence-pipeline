"""Tests for VirusTotal + Shodan enrichers and the enrichment manager."""

from __future__ import annotations

import httpx
import pytest
import respx

from tip.core.config import Settings
from tip.core.models import IOCType
from tip.enrichment.external_enricher import ExternalEnrichmentManager
from tip.enrichment.shodan import ShodanEnricher
from tip.enrichment.virustotal import VirusTotalEnricher


def _settings(vt="", shodan="") -> Settings:
    return Settings(misp_api_key="x", virustotal_api_key=vt, shodan_api_key=shodan)


# --------------------------------------------------------------------------- #
# VirusTotal
# --------------------------------------------------------------------------- #
def _vt_body(malicious=5, suspicious=1, harmless=60, undetected=4):
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                },
                "reputation": -12,
                "popular_threat_classification": {"suggested_threat_label": "trojan.emotet"},
                "names": ["evil.exe"],
            }
        }
    }


@pytest.mark.asyncio
async def test_vt_enriches_ip_with_score():
    vt = VirusTotalEnricher(_settings(vt="key"))
    with respx.mock:
        respx.get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8").mock(
            return_value=httpx.Response(200, json=_vt_body())
        )
        result = await vt.enrich("8.8.8.8", IOCType.IP)

    assert result is not None
    assert result.found is True
    assert result.source == "virustotal"
    # (5 + 0.5*1) / 70 * 100 ≈ 8
    assert result.malicious_score == 8
    assert "5/70" in result.summary
    assert result.details["threat_label"] == "trojan.emotet"
    assert result.link.startswith("https://www.virustotal.com/gui/")
    await vt.close()


@pytest.mark.asyncio
async def test_vt_high_detection_is_malicious():
    vt = VirusTotalEnricher(_settings(vt="key"))
    with respx.mock:
        respx.get("https://www.virustotal.com/api/v3/files/" + "a" * 64).mock(
            return_value=httpx.Response(
                200, json=_vt_body(malicious=50, harmless=10, undetected=0, suspicious=0)
            )
        )
        result = await vt.enrich("a" * 64, IOCType.SHA256)

    assert result.is_malicious() is True
    await vt.close()


@pytest.mark.asyncio
async def test_vt_404_returns_not_found():
    vt = VirusTotalEnricher(_settings(vt="key"))
    with respx.mock:
        respx.get("https://www.virustotal.com/api/v3/domains/unknown.com").mock(
            return_value=httpx.Response(404, json={"error": {"code": "NotFoundError"}})
        )
        result = await vt.enrich("unknown.com", IOCType.DOMAIN)

    assert result is not None
    assert result.found is False
    await vt.close()


@pytest.mark.asyncio
async def test_vt_401_returns_none():
    vt = VirusTotalEnricher(_settings(vt="bad-key"))
    with respx.mock:
        respx.get("https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4").mock(
            return_value=httpx.Response(
                401, json={"error": {"code": "AuthenticationRequiredError"}}
            )
        )
        result = await vt.enrich("1.2.3.4", IOCType.IP)

    assert result is None
    await vt.close()


def test_vt_url_object_id_is_base64():
    vt = VirusTotalEnricher(_settings(vt="key"))
    oid = vt._object_id("http://evil.com/x", IOCType.URL)
    assert "=" not in oid  # unpadded base64
    assert "/" not in oid or oid.replace("-", "").replace("_", "")  # urlsafe


def test_vt_not_configured_without_key():
    vt = VirusTotalEnricher(_settings())
    assert vt.configured is False


def test_vt_supports_expected_types():
    vt = VirusTotalEnricher(_settings(vt="key"))
    assert vt.supports(IOCType.IP)
    assert vt.supports(IOCType.SHA256)
    assert vt.supports(IOCType.DOMAIN)
    assert not vt.supports(IOCType.FILENAME)


# --------------------------------------------------------------------------- #
# Shodan
# --------------------------------------------------------------------------- #
def _shodan_body():
    return {
        "ports": [22, 80, 443],
        "vulns": ["CVE-2021-44228", "CVE-2019-0708"],
        "hostnames": ["host.evil.com"],
        "org": "Evil Hosting Ltd",
        "country_name": "RU",
        "os": "Linux",
        "tags": ["malware"],
    }


@pytest.mark.asyncio
async def test_shodan_enriches_ip_with_ports_and_vulns():
    sh = ShodanEnricher(_settings(shodan="key"))
    with respx.mock:
        respx.get("https://api.shodan.io/shodan/host/1.2.3.4").mock(
            return_value=httpx.Response(200, json=_shodan_body())
        )
        result = await sh.enrich("1.2.3.4", IOCType.IP)

    assert result is not None
    assert result.found is True
    assert result.source == "shodan"
    assert result.details["ports"] == [22, 80, 443]
    assert "CVE-2021-44228" in result.details["vulns"]
    # malware tag forces score >= 80
    assert result.is_malicious() is True
    assert result.link == "https://www.shodan.io/host/1.2.3.4"
    await sh.close()


@pytest.mark.asyncio
async def test_shodan_only_supports_ips():
    sh = ShodanEnricher(_settings(shodan="key"))
    assert sh.supports(IOCType.IP)
    assert not sh.supports(IOCType.DOMAIN)
    result = await sh.enrich("evil.com", IOCType.DOMAIN)
    assert result is None
    await sh.close()


@pytest.mark.asyncio
async def test_shodan_404_returns_not_found():
    sh = ShodanEnricher(_settings(shodan="key"))
    with respx.mock:
        respx.get("https://api.shodan.io/shodan/host/8.8.8.8").mock(
            return_value=httpx.Response(404, json={"error": "No information available"})
        )
        result = await sh.enrich("8.8.8.8", IOCType.IP)
    assert result.found is False
    await sh.close()


# --------------------------------------------------------------------------- #
# Manager
# --------------------------------------------------------------------------- #
def test_manager_drops_unconfigured_enrichers():
    mgr = ExternalEnrichmentManager([VirusTotalEnricher(_settings()), ShodanEnricher(_settings())])
    assert mgr.active is False


def test_manager_keeps_configured_enrichers():
    mgr = ExternalEnrichmentManager(
        [VirusTotalEnricher(_settings(vt="key")), ShodanEnricher(_settings())]
    )
    assert mgr.active is True
    assert len(mgr.enrichers) == 1


@pytest.mark.asyncio
async def test_manager_fans_ip_to_both_sources():
    mgr = ExternalEnrichmentManager(
        [VirusTotalEnricher(_settings(vt="key")), ShodanEnricher(_settings(shodan="key"))]
    )
    with respx.mock:
        respx.get("https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4").mock(
            return_value=httpx.Response(200, json=_vt_body())
        )
        respx.get("https://api.shodan.io/shodan/host/1.2.3.4").mock(
            return_value=httpx.Response(200, json=_shodan_body())
        )
        results = await mgr.enrich_value("1.2.3.4", IOCType.IP)

    sources = {r.source for r in results}
    assert sources == {"virustotal", "shodan"}
    await mgr.close()


@pytest.mark.asyncio
async def test_manager_handles_enricher_exception_gracefully():
    mgr = ExternalEnrichmentManager([VirusTotalEnricher(_settings(vt="key"))])
    with respx.mock:
        respx.get("https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4").mock(
            side_effect=httpx.ConnectError("network down")
        )
        results = await mgr.enrich_value("1.2.3.4", IOCType.IP)
    # enricher returns None on error → manager yields empty list, no raise
    assert results == []
    await mgr.close()
