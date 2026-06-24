"""Shodan enrichment provider (IP recon: ports, services, vulnerabilities)."""

from __future__ import annotations

import logging

import httpx

from tip.core.config import Settings
from tip.core.models import ExternalEnrichmentResult, IOCType
from tip.enrichment.external_enricher import ExternalEnricher

logger = logging.getLogger(__name__)


class ShodanEnricher(ExternalEnricher):
    name = "shodan"
    # Shodan host lookup is IP-only.
    supported_types = frozenset({IOCType.IP})

    def __init__(self, settings: Settings) -> None:
        self.api_key = settings.shodan_api_key
        self.base_url = settings.shodan_base_url.rstrip("/")
        self.client = httpx.AsyncClient(timeout=20)

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    async def enrich(self, value: str, ioc_type: IOCType) -> ExternalEnrichmentResult | None:
        if ioc_type != IOCType.IP:
            return None

        url = f"{self.base_url}/shodan/host/{value}"
        try:
            resp = await self.client.get(url, params={"key": self.api_key})
        except Exception as exc:
            logger.warning("Shodan request failed for %s: %s", value, exc)
            return None

        if resp.status_code == 404:
            return ExternalEnrichmentResult(
                source=self.name,
                ioc_value=value,
                found=False,
                summary="No Shodan data for this host",
            )
        if resp.status_code == 401:
            logger.warning("Shodan 401 — check TIP_SHODAN_API_KEY")
            return None
        if resp.status_code == 429:
            logger.warning("Shodan rate limit hit (429)")
            return None
        if resp.status_code != 200:
            return None

        return self._parse(value, resp.json())

    def _parse(self, value: str, body: dict) -> ExternalEnrichmentResult:
        ports = sorted({int(p) for p in body.get("ports", []) if isinstance(p, int)})
        vulns = sorted(body.get("vulns", []) or [])
        hostnames = body.get("hostnames", []) or []
        org = body.get("org") or body.get("isp") or ""
        country = body.get("country_name", "")
        os_name = body.get("os") or ""
        tags = body.get("tags", []) or []

        # Heuristic maliciousness: known CVEs and risky tags raise the score.
        score = 0
        if vulns:
            score = min(100, 40 + len(vulns) * 10)
        if any(t in ("malware", "compromised", "honeypot") for t in tags):
            score = max(score, 80)

        parts = [f"{len(ports)} open ports"]
        if vulns:
            parts.append(f"{len(vulns)} CVEs")
        if org:
            parts.append(org)
        if country:
            parts.append(country)
        summary = " · ".join(parts)

        return ExternalEnrichmentResult(
            source=self.name,
            ioc_value=value,
            found=True,
            malicious_score=score or None,
            summary=summary,
            details={
                "ports": ports,
                "vulns": vulns[:10],
                "hostnames": hostnames[:5],
                "org": org,
                "country": country,
                "os": os_name,
                "tags": tags,
            },
            link=f"https://www.shodan.io/host/{value}",
        )

    async def health_check(self) -> bool:
        if not self.configured:
            return False
        try:
            resp = await self.client.get(f"{self.base_url}/api-info", params={"key": self.api_key})
            return resp.status_code == 200
        except Exception:
            return False

    async def close(self) -> None:
        await self.client.aclose()
