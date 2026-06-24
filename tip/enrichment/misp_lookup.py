from __future__ import annotations

import ipaddress
import logging
import re
from datetime import datetime

from tip.core.models import IOC, IOCType, ThreatLevel
from tip.misp.client import MISPClient

logger = logging.getLogger(__name__)

# Regex patterns for extracting IOCs from raw text/fields
_IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_HASH_MD5_RE = re.compile(r'\b[0-9a-fA-F]{32}\b')
_HASH_SHA1_RE = re.compile(r'\b[0-9a-fA-F]{40}\b')
_HASH_SHA256_RE = re.compile(r'\b[0-9a-fA-F]{64}\b')
_DOMAIN_RE = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')

PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


class MISPLookup:
    def __init__(self, misp_client: MISPClient) -> None:
        self.misp = misp_client

    async def lookup_ioc(self, value: str) -> dict:
        """Look up a single IOC value in MISP."""
        context = await self.misp.get_ioc_context(value)
        matched = context.get("matched", False)

        ioc_obj: IOC | None = None
        if matched and context.get("attributes"):
            attr = context["attributes"][0]
            if isinstance(attr, dict):
                ioc_obj = self._attr_to_ioc(attr)

        return {"matched": matched, "ioc": ioc_obj, "context": context}

    async def lookup_alert_iocs(self, ioc_values: list[str]) -> list[IOC]:
        """Bulk lookup all IOC values extracted from an alert."""
        matched: list[IOC] = []
        results = await self.misp.lookup_many(ioc_values)

        for value, attributes in results.items():
            if not attributes:
                continue
            for attr in attributes:
                ioc = self._attr_to_ioc(attr) if isinstance(attr, dict) else None
                if ioc:
                    # Enrich with event context tags
                    context = await self.misp.get_ioc_context(value)
                    ioc = ioc.model_copy(update={
                        "tags": context.get("tags", ioc.tags),
                    })
                    matched.append(ioc)
                    break  # one match per value is enough

        return matched

    def extract_iocs_from_alert(self, alert: dict, source_siem: str) -> list[str]:
        """Extract IOC candidate values from a raw alert dict."""
        candidates: set[str] = set()

        if source_siem == "elastic":
            candidates.update(self._extract_elastic_iocs(alert))
        elif source_siem == "sentinel":
            candidates.update(self._extract_sentinel_iocs(alert))
        else:
            # Generic: scan all string values in the alert recursively
            candidates.update(self._extract_generic(alert))

        return [v for v in candidates if self._is_valid_ioc_candidate(v)]

    def _extract_elastic_iocs(self, alert: dict) -> set[str]:
        values: set[str] = set()
        field_paths = [
            "source.ip", "destination.ip", "network.destination.ip",
            "dns.question.name", "url.domain", "url.full",
            "process.hash.sha256", "file.hash.sha256", "file.hash.md5",
            "host.ip", "client.ip", "server.ip",
        ]
        # Elastic hits may have _source as nested OR as flat dot-notation keys
        source = alert.get("_source", alert)
        for path in field_paths:
            # Check flat key first (e.g., {"source.ip": "1.2.3.4"})
            flat_val = source.get(path)
            if flat_val and isinstance(flat_val, str):
                values.add(flat_val.strip())
                continue
            # Then try nested traversal
            val = self._deep_get(source, path)
            if val:
                values.add(str(val).strip())

        # Also look for flat dot-notation keys at the top level
        for key, val in source.items():
            if isinstance(val, str) and any(key.startswith(prefix) for prefix in
                                            ("source.", "destination.", "dns.", "url.", "file.", "process.")):
                values.add(val.strip())

        # Scan for IP/hash patterns in the raw alert
        values.update(self._scan_dict_for_iocs(alert))
        return values

    def _extract_sentinel_iocs(self, alert: dict) -> set[str]:
        values: set[str] = set()
        props = alert.get("properties", {})

        # Entities from Sentinel incidents
        entities = props.get("entities", [])
        for entity in entities:
            if not isinstance(entity, dict):
                continue
            # IP entities
            addr = entity.get("address")
            if addr:
                values.add(str(addr).strip())
            # Domain entities
            domain = entity.get("domainName")
            if domain:
                values.add(str(domain).strip())
            # URL entities
            url = entity.get("url")
            if url:
                values.add(str(url).strip())
            # Hash entities
            for fh in entity.get("fileHashes", []):
                if isinstance(fh, dict):
                    hv = fh.get("hashValue", "")
                    if hv:
                        values.add(hv.strip())
                elif isinstance(fh, str):
                    values.add(fh.strip())
            # File hash nested
            for key in ("md5", "sha1", "sha256"):
                hval = entity.get(key, "")
                if hval:
                    values.add(str(hval).strip())

        return values

    def _extract_generic(self, data: dict, depth: int = 0) -> set[str]:
        """Recursively extract all string values and scan for IOC patterns."""
        if depth > 5:
            return set()
        values: set[str] = set()
        for val in data.values():
            if isinstance(val, str):
                values.add(val)
            elif isinstance(val, dict):
                values.update(self._extract_generic(val, depth + 1))
            elif isinstance(val, list):
                for item in val:
                    if isinstance(item, str):
                        values.add(item)
                    elif isinstance(item, dict):
                        values.update(self._extract_generic(item, depth + 1))
        return values

    def _scan_dict_for_iocs(self, data: dict) -> set[str]:
        """Use regex to find IPs, hashes in string values."""
        found: set[str] = set()
        text = str(data)
        found.update(_IP_RE.findall(text))
        found.update(h.lower() for h in _HASH_SHA256_RE.findall(text))
        found.update(h.lower() for h in _HASH_MD5_RE.findall(text))
        return found

    def _deep_get(self, d: dict, path: str) -> str | None:
        """Get a dot-separated path from a nested dict."""
        keys = path.split(".")
        current = d
        for key in keys:
            if not isinstance(current, dict):
                return None
            current = current.get(key)
            if current is None:
                return None
        return str(current) if current is not None else None

    def _is_valid_ioc_candidate(self, value: str) -> bool:
        """Basic validation: not empty, not private IP, not localhost, not too short."""
        if not value or len(value) < 4:
            return False
        if value in ("0.0.0.0", "255.255.255.255", "localhost"):
            return False
        # Check if it looks like an IP
        if _IP_RE.fullmatch(value):
            try:
                addr = ipaddress.ip_address(value)
                if any(addr in net for net in PRIVATE_NETWORKS):
                    return False
                if addr.is_reserved or addr.is_multicast or addr.is_unspecified:
                    return False
            except ValueError:
                pass
        return True

    def _attr_to_ioc(self, attr: dict) -> IOC | None:
        """Convert a MISP attribute dict to an IOC model."""
        try:
            ioc_type_str = attr.get("type", "")
            try:
                ioc_type = IOCType(ioc_type_str)
            except ValueError:
                return None

            value = attr.get("value", "")
            if not value:
                return None

            tags = [t.get("name", "") if isinstance(t, dict) else str(t)
                    for t in attr.get("Tag", [])]

            event = attr.get("Event", {})
            event_info = event.get("info", "") if isinstance(event, dict) else ""

            return IOC(
                value=value,
                ioc_type=ioc_type,
                source_feed=event_info.split(" — ")[0] if " — " in event_info else "misp",
                threat_level=ThreatLevel.UNKNOWN,
                tags=tags,
                description=attr.get("comment", ""),
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                confidence=75,
                misp_event_id=str(attr.get("event_id", "")),
                misp_attribute_id=str(attr.get("id", "")),
                raw=attr,
            )
        except Exception as exc:
            logger.debug("attr_to_ioc conversion error: %s", exc)
            return None
