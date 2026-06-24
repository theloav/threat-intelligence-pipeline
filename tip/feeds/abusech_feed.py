from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from urllib.parse import urlparse

import httpx

from tip.core.config import Settings
from tip.core.models import IOC, IOCType, ThreatLevel
from tip.feeds.base import BaseFeed

logger = logging.getLogger(__name__)

# Abuse.ch APIs use form-encoded POST, not JSON
FORM_HEADERS = {"Content-Type": "application/x-www-form-urlencoded"}


def _parse_abusech_datetime(value: str) -> datetime:
    """Parse various Abuse.ch datetime formats gracefully."""
    if not value:
        return datetime.utcnow()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return datetime.utcnow()


class AbuseCHFeed(BaseFeed):
    name = "abusech"

    def __init__(self, settings: Settings) -> None:
        self.malware_url = settings.abusech_malware_url.rstrip("/") + "/"
        self.url_url = settings.abusech_url_url.rstrip("/") + "/"
        self.threatfox_url = settings.abusech_threatfox_url.rstrip("/") + "/"
        self.lookback_days = settings.abusech_lookback_days
        self.client = httpx.AsyncClient(timeout=30, headers=FORM_HEADERS)

    async def fetch(self) -> list[IOC]:
        results_malware, results_urlhaus, results_threatfox = await asyncio.gather(
            self._fetch_malwarebazaar(),
            self._fetch_urlhaus(),
            self._fetch_threatfox(),
            return_exceptions=True,
        )

        iocs: list[IOC] = []
        for result in [results_malware, results_urlhaus, results_threatfox]:
            if isinstance(result, Exception):
                logger.error("Abuse.ch sub-feed error: %s", result)
            else:
                iocs.extend(result)

        logger.info("Abuse.ch: total %d IOCs fetched", len(iocs))
        return iocs

    async def _fetch_malwarebazaar(self) -> list[IOC]:
        iocs: list[IOC] = []
        try:
            resp = await self.client.post(
                self.malware_url,
                data={"query": "get_recent", "selector": "time", "limit": 100},
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            logger.error("MalwareBazaar fetch error: %s", exc)
            return []

        if data.get("query_status") != "ok":
            logger.warning("MalwareBazaar query_status: %s", data.get("query_status"))
            return []

        for sample in data.get("data", []):
            sha256 = sample.get("sha256_hash", "").strip()
            if not sha256:
                continue

            md5 = sample.get("md5_hash", "").strip()
            file_name = sample.get("file_name", "").strip()
            signature = sample.get("signature", "") or "Unknown"
            file_type = sample.get("file_type", "") or "unknown"
            tags_raw = sample.get("tags") or []
            tags = list(tags_raw) if isinstance(tags_raw, list) else []
            if signature and signature not in tags:
                tags.append(signature)

            first_seen = _parse_abusech_datetime(sample.get("first_seen", ""))
            last_seen = _parse_abusech_datetime(sample.get("last_seen") or sample.get("first_seen", ""))
            description = f"{signature} malware sample — {file_type}"

            iocs.append(IOC(
                value=sha256,
                ioc_type=IOCType.SHA256,
                source_feed="abusech_malware",
                threat_level=ThreatLevel.HIGH,
                tags=tags,
                description=description,
                first_seen=first_seen,
                last_seen=last_seen,
                confidence=90,
                pulse_id=sha256,
                raw=sample,
            ))

            if md5:
                iocs.append(IOC(
                    value=md5,
                    ioc_type=IOCType.MD5,
                    source_feed="abusech_malware",
                    threat_level=ThreatLevel.HIGH,
                    tags=tags,
                    description=description,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    confidence=85,
                    pulse_id=sha256,
                    raw=sample,
                ))

            if file_name:
                iocs.append(IOC(
                    value=file_name,
                    ioc_type=IOCType.FILENAME,
                    source_feed="abusech_malware",
                    threat_level=ThreatLevel.MEDIUM,
                    tags=tags,
                    description=description,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    confidence=70,
                    pulse_id=sha256,
                    raw=sample,
                ))

        return iocs

    async def _fetch_urlhaus(self) -> list[IOC]:
        iocs: list[IOC] = []
        try:
            resp = await self.client.post(
                self.url_url + "urls/recent/",
                data={"limit": 100},
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            logger.error("URLhaus fetch error: %s", exc)
            return []

        for entry in data.get("urls", []):
            url_value = entry.get("url", "").strip()
            if not url_value:
                continue

            threat = entry.get("threat", "") or ""
            if "malware" in threat.lower():
                threat_level = ThreatLevel.HIGH
            elif "phishing" in threat.lower():
                threat_level = ThreatLevel.MEDIUM
            else:
                threat_level = ThreatLevel.MEDIUM

            tags_raw = entry.get("tags") or []
            tags = list(tags_raw) if isinstance(tags_raw, list) else []

            date_added = _parse_abusech_datetime(entry.get("date_added", ""))
            last_online = _parse_abusech_datetime(entry.get("date_added", ""))
            entry_id = str(entry.get("id", ""))

            iocs.append(IOC(
                value=url_value,
                ioc_type=IOCType.URL,
                source_feed="abusech_url",
                threat_level=threat_level,
                tags=tags,
                description=f"URLhaus — {threat}",
                first_seen=date_added,
                last_seen=last_online,
                confidence=80,
                pulse_id=entry_id,
                raw=entry,
            ))

            # Also add host as domain or IP IOC
            host = entry.get("host", "").strip()
            if not host:
                try:
                    host = urlparse(url_value).hostname or ""
                except Exception:
                    host = ""

            if host:
                host_type = self._classify_host(host)
                iocs.append(IOC(
                    value=host,
                    ioc_type=host_type,
                    source_feed="abusech_url",
                    threat_level=threat_level,
                    tags=tags,
                    description=f"URLhaus host — {threat}",
                    first_seen=date_added,
                    last_seen=last_online,
                    confidence=75,
                    pulse_id=entry_id,
                    raw=entry,
                ))

        return iocs

    async def _fetch_threatfox(self) -> list[IOC]:
        iocs: list[IOC] = []
        try:
            resp = await self.client.post(
                self.threatfox_url,
                data={"query": "get_iocs", "days": str(self.lookback_days)},
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            logger.error("ThreatFox fetch error: %s", exc)
            return []

        if data.get("query_status") != "ok":
            logger.warning("ThreatFox query_status: %s", data.get("query_status"))
            return []

        for entry in data.get("data", []):
            raw_type = entry.get("ioc_type", "")
            raw_value = entry.get("ioc", "").strip()
            if not raw_value:
                continue

            ioc_type, value = self._parse_threatfox_ioc(raw_type, raw_value)
            if ioc_type is None:
                continue

            confidence_level = int(entry.get("confidence_level", 50))
            if confidence_level >= 75:
                threat_level = ThreatLevel.HIGH
            elif confidence_level >= 50:
                threat_level = ThreatLevel.MEDIUM
            else:
                threat_level = ThreatLevel.LOW

            malware = entry.get("malware", "") or ""
            malware_alias = entry.get("malware_alias", "") or ""
            tags_raw = entry.get("tags") or []
            tags = list(tags_raw) if isinstance(tags_raw, list) else []
            for extra in [malware, malware_alias]:
                if extra and extra not in tags:
                    tags.append(extra)
            tags = [t for t in tags if t]

            first_seen = _parse_abusech_datetime(entry.get("first_seen", ""))
            last_seen = _parse_abusech_datetime(entry.get("last_seen") or entry.get("first_seen", ""))

            iocs.append(IOC(
                value=value,
                ioc_type=ioc_type,
                source_feed="threatfox",
                threat_level=threat_level,
                tags=tags,
                description=f"ThreatFox — {malware}",
                first_seen=first_seen,
                last_seen=last_seen,
                confidence=confidence_level,
                pulse_id=str(entry.get("id", "")),
                raw=entry,
            ))

        return iocs

    def _parse_threatfox_ioc(self, raw_type: str, raw_value: str) -> tuple[IOCType | None, str]:
        """Map ThreatFox ioc_type to IOCType, extract clean value."""
        if raw_type == "ip:port":
            ip = raw_value.split(":")[0] if ":" in raw_value else raw_value
            return IOCType.IP, ip
        elif raw_type == "domain":
            return IOCType.DOMAIN, raw_value
        elif raw_type == "url":
            return IOCType.URL, raw_value
        elif raw_type == "md5_hash":
            return IOCType.MD5, raw_value.lower()
        elif raw_type == "sha256_hash":
            return IOCType.SHA256, raw_value.lower()
        return None, raw_value

    def _classify_host(self, host: str) -> IOCType:
        """Return IP or DOMAIN based on whether host is numeric."""
        import ipaddress
        try:
            ipaddress.ip_address(host)
            return IOCType.IP
        except ValueError:
            return IOCType.DOMAIN

    async def health_check(self) -> bool:
        try:
            resp = await self.client.post(
                self.malware_url,
                data={"query": "get_info", "hash": "abc"},
            )
            return resp.status_code == 200
        except Exception:
            return False

    async def close(self) -> None:
        await self.client.aclose()
