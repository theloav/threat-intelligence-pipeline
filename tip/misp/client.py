from __future__ import annotations

import asyncio
import logging
from datetime import date

from tip.core.config import Settings
from tip.core.models import IOC, ThreatLevel

logger = logging.getLogger(__name__)

THREAT_LEVEL_ID: dict[ThreatLevel, str] = {
    ThreatLevel.HIGH: "1",
    ThreatLevel.MEDIUM: "2",
    ThreatLevel.LOW: "3",
    ThreatLevel.UNKNOWN: "4",
}


def _run_sync(coro):
    """Run a coroutine in the current event loop via asyncio.to_thread wrapper."""
    # We don't use this — instead we wrap the PyMISP calls with to_thread below.
    pass


class MISPClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._misp = None
        self._event_cache: dict[str, str] = {}  # title → event_id

    @property
    def configured(self) -> bool:
        return bool(self.settings.misp_api_key)

    def _get_misp(self):
        """Lazy-init PyMISP (import deferred so tests can mock easily)."""
        if not self.configured:
            raise RuntimeError("MISP API key not configured (TIP_MISP_API_KEY)")
        if self._misp is None:
            from pymisp import PyMISP

            self._misp = PyMISP(
                self.settings.misp_url,
                self.settings.misp_api_key,
                ssl=self.settings.misp_verify_ssl,
            )
        return self._misp

    async def health_check(self) -> bool:
        if not self.configured:
            return False
        try:
            misp = self._get_misp()
            result = await asyncio.to_thread(misp.get_server_setting, "MISP.live")
            return isinstance(result, dict) and result.get("value") is not False
        except Exception as exc:
            logger.debug("MISP health check failed: %s", exc)
            return False

    async def store_ioc(self, ioc: IOC) -> IOC:
        """Store a single IOC in MISP under a per-feed-per-date event."""
        title = f"{ioc.source_feed} — {date.today().isoformat()}"
        event_id = await self.get_or_create_event(title, ioc.threat_level)

        misp = self._get_misp()

        def _add_attribute():
            from pymisp import MISPAttribute

            attr = MISPAttribute()
            attr.type = ioc.ioc_type.value
            attr.value = ioc.value
            attr.comment = ioc.description[:255] if ioc.description else ""
            attr.to_ids = True
            return misp.add_attribute(event_id, attr)

        try:
            result = await asyncio.to_thread(_add_attribute)
            if isinstance(result, dict) and "Attribute" in result:
                attr = result["Attribute"]
                ioc = ioc.model_copy(
                    update={
                        "misp_event_id": event_id,
                        "misp_attribute_id": str(attr.get("id", "")),
                    }
                )
            elif hasattr(result, "id"):
                ioc = ioc.model_copy(
                    update={
                        "misp_event_id": event_id,
                        "misp_attribute_id": str(result.id),
                    }
                )
        except Exception as exc:
            logger.warning("MISP add_attribute failed for %s: %s", ioc.value, exc)
            ioc = ioc.model_copy(update={"misp_event_id": event_id})

        # Add tags (best-effort)
        await self._add_tags_to_event(event_id, ioc.tags)

        return ioc

    async def store_iocs_batch(self, iocs: list[IOC]) -> list[IOC]:
        """Group IOCs by source_feed and store."""
        from itertools import groupby

        stored: list[IOC] = []
        sorted_iocs = sorted(iocs, key=lambda i: i.source_feed)
        for _feed, group in groupby(sorted_iocs, key=lambda i: i.source_feed):
            for ioc in group:
                try:
                    stored.append(await self.store_ioc(ioc))
                except Exception as exc:
                    logger.error("Batch store failed for %s: %s", ioc.value, exc)
        return stored

    async def lookup(self, value: str) -> list[dict]:
        """Search MISP for an IOC value. Returns [] if MISP is not configured."""
        if not self.configured:
            return []
        try:
            misp = self._get_misp()
            results = await asyncio.to_thread(misp.search, value=value, pythonify=False)
            if isinstance(results, list):
                return results
            return []
        except Exception as exc:
            logger.error("MISP lookup failed for %s: %s", value, exc)
            return []

    async def lookup_many(self, values: list[str]) -> dict[str, list[dict]]:
        """Bulk lookup. Returns dict mapping value → MISP attributes."""
        out: dict[str, list[dict]] = {}
        for val in values:
            out[val] = await self.lookup(val)
        return out

    async def get_or_create_event(self, title: str, threat_level: ThreatLevel) -> str:
        """Return existing event ID or create new event."""
        if title in self._event_cache:
            return self._event_cache[title]

        misp = self._get_misp()

        def _search_event():
            return misp.search_index(eventinfo=title, pythonify=False)

        try:
            existing = await asyncio.to_thread(_search_event)
            if isinstance(existing, list) and existing:
                event = existing[0]
                event_id = str(event.get("id", "") if isinstance(event, dict) else event.id)
                self._event_cache[title] = event_id
                return event_id
        except Exception:
            pass

        def _create_event():
            from pymisp import MISPEvent as PyMISPEvent

            event = PyMISPEvent()
            event.info = title
            event.threat_level_id = THREAT_LEVEL_ID.get(threat_level, "4")
            event.analysis = 0  # Initial
            event.distribution = 0  # Your org only
            return misp.add_event(event)

        try:
            result = await asyncio.to_thread(_create_event)
            if isinstance(result, dict) and "Event" in result:
                event_id = str(result["Event"]["id"])
            elif hasattr(result, "id"):
                event_id = str(result.id)
            else:
                event_id = str(result)
            self._event_cache[title] = event_id
            return event_id
        except Exception as exc:
            logger.error("MISP create event failed: %s", exc)
            raise

    async def get_ioc_context(self, value: str) -> dict:
        """Full enrichment context for a single IOC value."""
        attributes = await self.lookup(value)
        if not attributes:
            return {
                "matched": False,
                "attributes": [],
                "events": [],
                "tags": [],
                "threat_actors": [],
                "campaigns": [],
                "feeds": [],
            }

        all_tags: set[str] = set()
        threat_actors: list[str] = []
        campaigns: list[str] = []
        events: list[dict] = []
        feeds: set[str] = set()

        for attr in attributes:
            event_data = attr.get("Event", {}) if isinstance(attr, dict) else {}
            if event_data:
                events.append(event_data)
                info = event_data.get("info", "")
                # Extract source feed from event title pattern "feed — date"
                if " — " in info:
                    feeds.add(info.split(" — ")[0].strip())

            for tag in attr.get("Tag", []) if isinstance(attr, dict) else []:
                tag_name = tag.get("name", "") if isinstance(tag, dict) else str(tag)
                all_tags.add(tag_name)
                if tag_name.startswith("threat-actor:"):
                    threat_actors.append(tag_name.replace("threat-actor:", "").strip())
                elif "threat-actor" in tag_name.lower():
                    campaigns.append(tag_name)

        return {
            "matched": True,
            "attributes": attributes,
            "events": events,
            "tags": sorted(all_tags),
            "threat_actors": list(dict.fromkeys(threat_actors)),
            "campaigns": list(dict.fromkeys(campaigns)),
            "feeds": sorted(feeds),
        }

    async def _add_tags_to_event(self, event_id: str, tags: list[str]) -> None:
        if not tags:
            return
        misp = self._get_misp()
        for tag in tags[:10]:  # limit tag writes per call
            try:
                await asyncio.to_thread(misp.tag, event_id, tag, local=False)
            except Exception:
                pass  # tags are best-effort
