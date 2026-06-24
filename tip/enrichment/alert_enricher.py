from __future__ import annotations

import logging
from datetime import datetime
from typing import TYPE_CHECKING

from tip.core.models import EnrichedAlert, IOC
from tip.core.scoring import score_iocs_batch
from tip.enrichment.misp_lookup import MISPLookup
from tip.enrichment.tag_writer import TagWriter

if TYPE_CHECKING:
    from tip.notification.slack_notifier import SlackNotifier
    from tip.siem.elastic_client import ElasticClient
    from tip.siem.sentinel_client import SentinelClient

logger = logging.getLogger(__name__)


class AlertEnricher:
    def __init__(
        self,
        misp_lookup: MISPLookup,
        tag_writer: TagWriter,
        sentinel_client: "SentinelClient | None",
        elastic_client: "ElasticClient | None",
        slack_notifier: "SlackNotifier",
        notify_on: list[str] | None = None,
    ) -> None:
        self.misp_lookup = misp_lookup
        self.tag_writer = tag_writer
        self.sentinel = sentinel_client
        self.elastic = elastic_client
        self.slack = slack_notifier
        self.notify_on = {s.lower() for s in (notify_on or ["high", "critical"])}

    async def enrich_alert(self, alert: dict, source_siem: str) -> EnrichedAlert:
        """Full enrichment pipeline for a single alert."""
        alert_id = self._extract_alert_id(alert, source_siem)
        alert_name = self._extract_alert_name(alert, source_siem)
        severity = self._extract_severity(alert, source_siem)
        triggered_at = self._extract_timestamp(alert, source_siem)

        # 1. Extract IOC values from alert fields
        extracted = self.misp_lookup.extract_iocs_from_alert(alert, source_siem)

        # 2. Lookup each in MISP
        matched_iocs: list[IOC] = []
        if extracted:
            matched_iocs = await self.misp_lookup.lookup_alert_iocs(extracted)

        # Score matched IOCs
        if matched_iocs:
            matched_iocs = score_iocs_batch(matched_iocs)

        # 3. Collect threat actors, campaigns, tags
        threat_actors: list[str] = []
        campaigns: list[str] = []
        attack_techniques: set[str] = set()

        for ioc in matched_iocs:
            for tag in ioc.tags:
                tl = tag.lower()
                if "threat-actor:" in tl:
                    actor = tag.replace("threat-actor:", "").strip()
                    if actor not in threat_actors:
                        threat_actors.append(actor)
                elif "misp-galaxy:threat-actor" in tl:
                    campaign = tag.split("=")[-1].strip('"')
                    if campaign not in campaigns:
                        campaigns.append(campaign)
            attack_techniques.update(ioc.attack_techniques)

        # 4. Build enrichment tags
        enrichment_tags = self.tag_writer.build_enrichment_tags(matched_iocs)

        # 5. Write tags back to SIEM (best-effort)
        if enrichment_tags and alert_id:
            try:
                await self.tag_writer.write_tags(alert_id, source_siem, enrichment_tags)
            except Exception as exc:
                logger.warning("Tag write failed for alert %s: %s", alert_id, exc)

        # Compute risk score (max threat_score of matched IOCs)
        risk_score = max((ioc.threat_score for ioc in matched_iocs), default=0.0)

        enriched = EnrichedAlert(
            alert_id=alert_id,
            alert_name=alert_name,
            severity=severity,
            source_siem=source_siem,
            triggered_at=triggered_at,
            raw_alert=alert,
            extracted_iocs=extracted,
            matched_iocs=matched_iocs,
            threat_actors=threat_actors,
            campaigns=campaigns,
            enrichment_tags=enrichment_tags,
            enriched_at=datetime.utcnow(),
            notification_sent=False,
            risk_score=risk_score,
            attack_techniques=sorted(attack_techniques),
        )

        # 5. Notify if matched and severity qualifies
        if matched_iocs and severity.lower() in self.notify_on:
            try:
                sent = await self.slack.notify_enriched_alert(enriched)
                enriched = enriched.model_copy(update={"notification_sent": sent})
            except Exception as exc:
                logger.error("Slack notification failed: %s", exc)

        return enriched

    async def enrich_elastic_alerts(self, since: datetime) -> list[EnrichedAlert]:
        if self.elastic is None:
            logger.info("Elastic client not configured — skipping")
            return []
        alerts = await self.elastic.get_alerts(since)
        results: list[EnrichedAlert] = []
        for alert in alerts:
            try:
                results.append(await self.enrich_alert(alert, "elastic"))
            except Exception as exc:
                logger.error("Elastic alert enrichment failed: %s", exc)
        return results

    async def enrich_sentinel_alerts(self, since: datetime) -> list[EnrichedAlert]:
        if self.sentinel is None:
            logger.info("Sentinel client not configured — skipping")
            return []
        alerts = await self.sentinel.get_incidents(since)
        results: list[EnrichedAlert] = []
        for alert in alerts:
            try:
                results.append(await self.enrich_alert(alert, "sentinel"))
            except Exception as exc:
                logger.error("Sentinel alert enrichment failed: %s", exc)
        return results

    async def run_enrichment_cycle(self, lookback_minutes: int = 60) -> dict:
        """Run one enrichment cycle across all configured SIEMs."""
        from datetime import timedelta
        since = datetime.utcnow() - timedelta(minutes=lookback_minutes)

        elastic_results = await self.enrich_elastic_alerts(since)
        sentinel_results = await self.enrich_sentinel_alerts(since)

        all_results = elastic_results + sentinel_results
        matched = sum(1 for r in all_results if r.has_matches())
        notified = sum(1 for r in all_results if r.notification_sent)

        return {
            "elastic": len(elastic_results),
            "sentinel": len(sentinel_results),
            "total": len(all_results),
            "matched": matched,
            "notified": notified,
        }

    # --- Field extraction helpers ---

    def _extract_alert_id(self, alert: dict, source_siem: str) -> str:
        if source_siem == "elastic":
            return alert.get("_id", alert.get("kibana.alert.uuid", "unknown"))
        elif source_siem == "sentinel":
            return alert.get("name", alert.get("id", "unknown"))
        return alert.get("id", "unknown")

    def _extract_alert_name(self, alert: dict, source_siem: str) -> str:
        if source_siem == "elastic":
            source = alert.get("_source", alert)
            return (
                source.get("kibana.alert.rule.name")
                or source.get("rule", {}).get("name", "Unknown Alert")
                if isinstance(source.get("rule"), dict)
                else source.get("kibana.alert.rule.name", "Unknown Alert")
            )
        elif source_siem == "sentinel":
            props = alert.get("properties", {})
            return props.get("title", alert.get("name", "Unknown Incident"))
        return alert.get("name", "Unknown")

    def _extract_severity(self, alert: dict, source_siem: str) -> str:
        if source_siem == "elastic":
            source = alert.get("_source", alert)
            return str(source.get("kibana.alert.severity", source.get("severity", "medium"))).lower()
        elif source_siem == "sentinel":
            props = alert.get("properties", {})
            return str(props.get("severity", "Medium")).lower()
        return "medium"

    def _extract_timestamp(self, alert: dict, source_siem: str) -> datetime:
        try:
            if source_siem == "elastic":
                source = alert.get("_source", alert)
                ts = source.get("@timestamp") or source.get("kibana.alert.start")
                if ts:
                    return datetime.fromisoformat(ts.replace("Z", "+00:00")).replace(tzinfo=None)
            elif source_siem == "sentinel":
                props = alert.get("properties", {})
                ts = props.get("createdTimeUtc")
                if ts:
                    return datetime.fromisoformat(ts.replace("Z", "+00:00")).replace(tzinfo=None)
        except (ValueError, AttributeError):
            pass
        return datetime.utcnow()
