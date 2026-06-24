"""VirusTotal v3 enrichment provider."""

from __future__ import annotations

import base64
import logging

import httpx

from tip.core.config import Settings
from tip.core.models import ExternalEnrichmentResult, IOCType
from tip.enrichment.external_enricher import ExternalEnricher

logger = logging.getLogger(__name__)

# Map our IOC types to VirusTotal v3 API endpoints.
_VT_ENDPOINTS: dict[IOCType, str] = {
    IOCType.IP: "ip_addresses",
    IOCType.DOMAIN: "domains",
    IOCType.URL: "urls",
    IOCType.MD5: "files",
    IOCType.SHA1: "files",
    IOCType.SHA256: "files",
}

_VT_GUI: dict[IOCType, str] = {
    IOCType.IP: "ip-address",
    IOCType.DOMAIN: "domain",
    IOCType.URL: "url",
    IOCType.MD5: "file",
    IOCType.SHA1: "file",
    IOCType.SHA256: "file",
}


class VirusTotalEnricher(ExternalEnricher):
    name = "virustotal"
    supported_types = frozenset(_VT_ENDPOINTS.keys())

    def __init__(self, settings: Settings) -> None:
        self.api_key = settings.virustotal_api_key
        self.base_url = settings.virustotal_base_url.rstrip("/")
        self.client = httpx.AsyncClient(
            headers={"x-apikey": self.api_key, "Accept": "application/json"},
            timeout=20,
        )

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    def _object_id(self, value: str, ioc_type: IOCType) -> str:
        """VT v3 object IDs: URLs are unpadded base64; others are the value."""
        if ioc_type == IOCType.URL:
            return base64.urlsafe_b64encode(value.encode()).decode().strip("=")
        return value

    async def enrich(self, value: str, ioc_type: IOCType) -> ExternalEnrichmentResult | None:
        endpoint = _VT_ENDPOINTS.get(ioc_type)
        if endpoint is None:
            return None

        object_id = self._object_id(value, ioc_type)
        url = f"{self.base_url}/{endpoint}/{object_id}"

        try:
            resp = await self.client.get(url)
        except Exception as exc:
            logger.warning("VirusTotal request failed for %s: %s", value, exc)
            return None

        if resp.status_code == 404:
            return ExternalEnrichmentResult(
                source=self.name,
                ioc_value=value,
                found=False,
                summary="Not found in VirusTotal",
            )
        if resp.status_code == 401:
            logger.warning("VirusTotal 401 — check TIP_VIRUSTOTAL_API_KEY")
            return None
        if resp.status_code == 429:
            logger.warning("VirusTotal rate limit hit (429)")
            return None
        if resp.status_code != 200:
            return None

        return self._parse(value, ioc_type, resp.json())

    def _parse(self, value: str, ioc_type: IOCType, body: dict) -> ExternalEnrichmentResult:
        attrs = body.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {}) or {}
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        undetected = int(stats.get("undetected", 0))
        total = malicious + suspicious + harmless + undetected

        score = round((malicious + 0.5 * suspicious) / total * 100) if total else None

        reputation = attrs.get("reputation")
        names = attrs.get("names") or []
        threat_label = attrs.get("popular_threat_classification", {}).get("suggested_threat_label")

        parts = [f"{malicious}/{total} engines flagged malicious"]
        if threat_label:
            parts.append(f"label={threat_label}")
        if reputation is not None:
            parts.append(f"reputation={reputation}")
        summary = " · ".join(parts)

        gui = _VT_GUI.get(ioc_type, "search")
        gui_id = self._object_id(value, ioc_type)
        link = f"https://www.virustotal.com/gui/{gui}/{gui_id}"

        return ExternalEnrichmentResult(
            source=self.name,
            ioc_value=value,
            found=True,
            malicious_score=score,
            summary=summary,
            details={
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "total_engines": total,
                "reputation": reputation,
                "threat_label": threat_label,
                "names": names[:5],
            },
            link=link,
        )

    async def health_check(self) -> bool:
        if not self.configured:
            return False
        try:
            # Quotas endpoint is cheap and validates the key.
            resp = await self.client.get(f"{self.base_url}/ip_addresses/8.8.8.8")
            return resp.status_code in (200, 404)
        except Exception:
            return False

    async def close(self) -> None:
        await self.client.aclose()
