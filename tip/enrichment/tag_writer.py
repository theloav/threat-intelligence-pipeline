from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from tip.core.models import IOC
from tip.core.timeutil import utcnow

if TYPE_CHECKING:
    from tip.siem.elastic_client import ElasticClient
    from tip.siem.sentinel_client import SentinelClient

logger = logging.getLogger(__name__)


class TagWriter:
    def __init__(
        self,
        sentinel_client: SentinelClient | None,
        elastic_client: ElasticClient | None,
    ) -> None:
        self.sentinel = sentinel_client
        self.elastic = elastic_client

    async def tag_elastic_alert(self, alert_id: str, tags: list[str]) -> bool:
        if self.elastic is None:
            return False
        update_body = {
            "doc": {
                "kibana.alert.workflow_tags": tags,
                "tip.enriched": True,
                "tip.tags": tags,
                "tip.enriched_at": utcnow().isoformat(),
            }
        }
        return await self.elastic.update_alert(alert_id, update_body)

    async def tag_sentinel_alert(self, alert_id: str, tags: list[str]) -> bool:
        if self.sentinel is None:
            return False
        return await self.sentinel.update_incident_labels(alert_id, tags)

    def build_enrichment_tags(self, matched_iocs: list[IOC]) -> list[str]:
        if not matched_iocs:
            return []

        tags: list[str] = ["tip:matched"]

        feeds = {ioc.source_feed for ioc in matched_iocs}
        for feed in sorted(feeds):
            tags.append(f"tip:feed:{feed}")

        actors: set[str] = set()
        for ioc in matched_iocs:
            for tag in ioc.tags:
                tl = tag.lower()
                if tl.startswith("threat-actor:"):
                    actors.add(tag.replace("threat-actor:", "").strip())
                elif any(known in tl for known in ("apt", "lazarus", "carbanak", "fin7", "ta505")):
                    actors.add(tag.strip())
        for actor in sorted(actors):
            tags.append(f"tip:actor:{actor}")

        ioc_types = {ioc.ioc_type.value for ioc in matched_iocs}
        for t in sorted(ioc_types):
            tags.append(f"tip:ioc-type:{t}")

        # MITRE ATT&CK techniques
        techniques: set[str] = set()
        for ioc in matched_iocs:
            techniques.update(ioc.attack_techniques)
        for tech in sorted(techniques):
            tags.append(f"tip:attack:{tech}")

        return tags

    async def write_tags(self, alert_id: str, source_siem: str, tags: list[str]) -> bool:
        """Route tag writing to the correct SIEM."""
        if source_siem == "elastic":
            return await self.tag_elastic_alert(alert_id, tags)
        elif source_siem == "sentinel":
            return await self.tag_sentinel_alert(alert_id, tags)
        logger.warning("Unknown SIEM for tag writing: %s", source_siem)
        return False
