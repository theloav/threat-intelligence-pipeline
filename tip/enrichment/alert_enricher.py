from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from tip.core.models import IOC, EnrichedAlert, ExternalEnrichmentResult
from tip.core.scoring import score_iocs_batch
from tip.core.timeutil import utcnow
from tip.enrichment.misp_lookup import MISPLookup
from tip.enrichment.tag_writer import TagWriter

if TYPE_CHECKING:
    from tip.enrichment.external_enricher import ExternalEnrichmentManager
    from tip.notification.slack_notifier import SlackNotifier
    from tip.siem.elastic_client import ElasticClient
    from tip.siem.sentinel_client import SentinelClient

logger = logging.getLogger(__name__)


class AlertEnricher:
    def __init__(
        self,
        misp_lookup: MISPLookup,
        tag_writer: TagWriter,
        sentinel_client: SentinelClient | None,
        elastic_client: ElasticClient | None,
        slack_notifier: SlackNotifier,
        notify_on: list[str] | None = None,
        external_manager: ExternalEnrichmentManager | None = None,
        enrich_unmatched: bool = False,
    ) -> None:
        self.misp_lookup = misp_lookup
        self.tag_writer = tag_writer
        self.sentinel = sentinel_client
        self.elastic = elastic_client
        self.slack = slack_notifier
        self.notify_on = {s.lower() for s in (notify_on or ["high", "critical"])}
        self.external_manager = external_manager
        self.enrich_unmatched = enrich_unmatched

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

        # 4. External enrichment (VirusTotal / Shodan) — optional
        external = await self._run_external_enrichment(matched_iocs, extracted)

        # 5. Build enrichment tags
        enrichment_tags = self.tag_writer.build_enrichment_tags(matched_iocs)
        enrichment_tags.extend(self._external_tags(external))

        # 6. Write tags back to SIEM (best-effort)
        if enrichment_tags and alert_id:
            try:
                await self.tag_writer.write_tags(alert_id, source_siem, enrichment_tags)
            except Exception as exc:
                logger.warning("Tag write failed for alert %s: %s", alert_id, exc)

        # Compute risk score (max threat_score of matched IOCs), boosted by
        # external verdicts so VT/Shodan can raise the score on their own.
        risk_score = max((ioc.threat_score for ioc in matched_iocs), default=0.0)
        external_max = max((r.malicious_score or 0 for r in external), default=0)
        risk_score = max(risk_score, float(external_max))

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
            enriched_at=utcnow(),
            notification_sent=False,
            risk_score=risk_score,
            attack_techniques=sorted(attack_techniques),
            external_enrichment=external,
        )

        # 7. Notify if (MISP match OR external malicious verdict) and severity qualifies
        external_malicious = any(r.is_malicious() for r in external)
        if (matched_iocs or external_malicious) and severity.lower() in self.notify_on:
            try:
                sent = await self.slack.notify_enriched_alert(enriched)
                enriched = enriched.model_copy(update={"notification_sent": sent})
            except Exception as exc:
                logger.error("Slack notification failed: %s", exc)

        return enriched

    async def _run_external_enrichment(
        self, matched_iocs: list[IOC], extracted: list[str]
    ) -> list[ExternalEnrichmentResult]:
        """Enrich matched IOCs (and optionally unmatched values) via VT/Shodan."""
        if self.external_manager is None or not self.external_manager.active:
            return []
        try:
            results = await self.external_manager.enrich_iocs(matched_iocs)
            if self.enrich_unmatched:
                matched_values = {ioc.value for ioc in matched_iocs}
                unmatched = [v for v in extracted if v not in matched_values]
                # Reuse extraction type inference: look these up as best-effort.
                for value in unmatched:
                    ioc_type = self._infer_type(value)
                    if ioc_type is not None:
                        results.extend(await self.external_manager.enrich_value(value, ioc_type))
            return results
        except Exception as exc:
            logger.warning("External enrichment failed: %s", exc)
            return []

    @staticmethod
    def _infer_type(value: str):
        import ipaddress
        import re

        from tip.core.models import IOCType

        try:
            ipaddress.ip_address(value)
            return IOCType.IP
        except ValueError:
            pass
        if re.fullmatch(r"[0-9a-fA-F]{64}", value):
            return IOCType.SHA256
        if re.fullmatch(r"[0-9a-fA-F]{32}", value):
            return IOCType.MD5
        if value.startswith(("http://", "https://")):
            return IOCType.URL
        if "." in value and " " not in value:
            return IOCType.DOMAIN
        return None

    @staticmethod
    def _external_tags(results: list[ExternalEnrichmentResult]) -> list[str]:
        tags: list[str] = []
        for r in results:
            if r.found and r.is_malicious():
                tags.append(f"tip:{r.source}:malicious")
            elif r.found:
                tags.append(f"tip:{r.source}:seen")
        return tags

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

    async def run_enrichment_cycle(
        self, lookback_minutes: int = 60, since: datetime | None = None
    ) -> dict:
        """Run one enrichment cycle across all configured SIEMs.

        If ``since`` is provided it takes precedence over ``lookback_minutes``.
        """
        if since is None:
            since = utcnow() - timedelta(minutes=lookback_minutes)

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
            return str(
                source.get("kibana.alert.severity", source.get("severity", "medium"))
            ).lower()
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
        return utcnow()
