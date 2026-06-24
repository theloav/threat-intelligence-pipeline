from __future__ import annotations

import logging
from datetime import datetime, timezone

import httpx

from tip.core.config import Settings
from tip.core.models import IOC, IOCType, ThreatLevel
from tip.feeds.base import BaseFeed

logger = logging.getLogger(__name__)

OTX_TYPE_MAP: dict[str, IOCType] = {
    "IPv4": IOCType.IP,
    "IPv6": IOCType.IP,
    "domain": IOCType.DOMAIN,
    "hostname": IOCType.DOMAIN,
    "URL": IOCType.URL,
    "FileHash-MD5": IOCType.MD5,
    "FileHash-SHA256": IOCType.SHA256,
    "FileHash-SHA1": IOCType.SHA1,
    "email": IOCType.EMAIL,
}

TLP_TO_THREAT_LEVEL: dict[str, ThreatLevel] = {
    "red": ThreatLevel.HIGH,
    "amber": ThreatLevel.MEDIUM,
    "green": ThreatLevel.LOW,
    "white": ThreatLevel.LOW,
}


class OTXFeed(BaseFeed):
    name = "otx"

    def __init__(self, settings: Settings) -> None:
        self.api_key = settings.otx_api_key
        self.base_url = settings.otx_base_url.rstrip("/")
        self.pulse_limit = settings.otx_pulse_limit
        self.lookback_days = settings.otx_lookback_days
        self.client = httpx.AsyncClient(
            headers={"X-OTX-API-KEY": self.api_key},
            timeout=30,
        )

    async def fetch(self) -> list[IOC]:
        iocs: list[IOC] = []
        since = self.get_lookback_since_naive(self.lookback_days)
        since_str = since.strftime("%Y-%m-%dT%H:%M:%S")

        try:
            resp = await self.client.get(
                f"{self.base_url}/pulses/subscribed",
                params={"modified_since": since_str, "limit": self.pulse_limit},
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            logger.error("OTX fetch failed: %s", exc)
            return []

        for pulse in data.get("results", []):
            pulse_iocs = self._parse_pulse(pulse)
            iocs.extend(pulse_iocs)

        logger.info("OTX: fetched %d IOCs from %d pulses", len(iocs), len(data.get("results", [])))
        return iocs

    def _parse_pulse(self, pulse: dict) -> list[IOC]:
        iocs: list[IOC] = []
        pulse_id = pulse.get("id", "")
        pulse_name = pulse.get("name", "")
        pulse_tags = pulse.get("tags", [])
        adversary = pulse.get("adversary", "")
        tlp = pulse.get("TLP", "white").lower()
        threat_level = TLP_TO_THREAT_LEVEL.get(tlp, ThreatLevel.UNKNOWN)

        all_tags = list(pulse_tags)
        if adversary:
            all_tags.append(adversary)
        all_tags = [t for t in all_tags if t]

        # MITRE ATT&CK techniques from pulse
        attack_techniques = [
            ref["external_id"]
            for ref in pulse.get("references", [])
            if isinstance(ref, dict) and "T" in str(ref.get("external_id", ""))
        ]
        # Also look in attack_ids
        attack_techniques.extend(pulse.get("attack_ids", []))
        attack_techniques = list(dict.fromkeys(attack_techniques))  # deduplicate

        created = pulse.get("created", datetime.utcnow().isoformat())
        modified = pulse.get("modified", created)

        try:
            first_seen = datetime.fromisoformat(created.replace("Z", "+00:00")).replace(tzinfo=None)
            last_seen = datetime.fromisoformat(modified.replace("Z", "+00:00")).replace(tzinfo=None)
        except (ValueError, AttributeError):
            first_seen = last_seen = datetime.utcnow()

        for indicator in pulse.get("indicators", []):
            ioc_type_str = indicator.get("type", "")
            ioc_type = OTX_TYPE_MAP.get(ioc_type_str)
            if ioc_type is None:
                continue

            value = str(indicator.get("indicator", "")).strip()
            if not value:
                continue

            description = indicator.get("description", "") or f"OTX pulse: {pulse_name}"
            confidence = min(100, max(0, int(pulse.get("pulse_source", {}).get("indicator_count", 50) if isinstance(pulse.get("pulse_source"), dict) else 70)))

            ioc = IOC(
                value=value,
                ioc_type=ioc_type,
                source_feed="otx",
                threat_level=threat_level,
                tags=all_tags,
                description=description,
                first_seen=first_seen,
                last_seen=last_seen,
                confidence=confidence,
                pulse_id=pulse_id,
                raw={"pulse_id": pulse_id, "pulse_name": pulse_name, "indicator": indicator},
                attack_techniques=attack_techniques,
            )
            iocs.append(ioc)

        return iocs

    async def fetch_pulse(self, pulse_id: str) -> dict:
        resp = await self.client.get(f"{self.base_url}/pulses/{pulse_id}")
        resp.raise_for_status()
        return resp.json()

    async def health_check(self) -> bool:
        try:
            resp = await self.client.get(f"{self.base_url}/user/me")
            return resp.status_code == 200
        except Exception:
            return False

    async def close(self) -> None:
        await self.client.aclose()
