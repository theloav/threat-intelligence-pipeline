from __future__ import annotations

import logging

import httpx

from tip.core.config import Settings
from tip.core.models import EnrichedAlert, FeedIngestionResult

logger = logging.getLogger(__name__)

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
}

SIEM_EMOJI = {
    "sentinel": "☁️",
    "elastic": "🔍",
}


class SlackNotifier:
    def __init__(self, settings: Settings) -> None:
        self.webhook_url = settings.slack_webhook_url
        self.notify_on = {s.lower() for s in settings.slack_notify_on}
        self.client = httpx.AsyncClient(timeout=10)

    def should_notify(self, severity: str) -> bool:
        return bool(self.webhook_url) and severity.lower() in self.notify_on

    async def notify_enriched_alert(self, alert: EnrichedAlert) -> bool:
        if not self.should_notify(alert.severity):
            return False
        if not alert.has_matches():
            return False
        message = self.build_message(alert)
        return await self.send(message)

    def build_message(self, alert: EnrichedAlert) -> dict:
        sev_emoji = SEVERITY_EMOJI.get(alert.severity.lower(), "⚠️")
        siem_emoji = SIEM_EMOJI.get(alert.source_siem.lower(), "📊")

        # Header
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🚨 ALERT: {alert.alert_name[:150]}",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Severity:* {sev_emoji} {alert.severity.upper()}"},
                    {
                        "type": "mrkdwn",
                        "text": f"*Source SIEM:* {siem_emoji} {alert.source_siem.title()}",
                    },
                    {"type": "mrkdwn", "text": f"*Alert ID:* `{alert.alert_id}`"},
                    {
                        "type": "mrkdwn",
                        "text": f"*Triggered:* {alert.triggered_at.strftime('%Y-%m-%d %H:%M UTC')}",
                    },
                ],
            },
            {"type": "divider"},
        ]

        # IOC Matches
        ioc_lines = []
        for ioc in alert.matched_iocs[:5]:
            score_indicator = (
                "🔴" if ioc.threat_score >= 75 else "🟡" if ioc.threat_score >= 50 else "🟢"
            )
            desc = ioc.description[:60] + "..." if len(ioc.description) > 60 else ioc.description
            ioc_lines.append(f"{score_indicator} `{ioc.ioc_type.value}` *{ioc.value}* — {desc}")
        if len(alert.matched_iocs) > 5:
            ioc_lines.append(f"_...and {len(alert.matched_iocs) - 5} more matches_")

        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*🎯 IOC Matches ({len(alert.matched_iocs)} found)*\n"
                    + "\n".join(ioc_lines),
                },
            }
        )

        # Threat Context
        actors = ", ".join(alert.threat_actors[:5]) or "Unknown"
        campaigns = ", ".join(alert.campaigns[:3]) or "Unknown"
        feeds = list({ioc.source_feed for ioc in alert.matched_iocs})
        techniques = ", ".join(alert.attack_techniques[:5]) or "None identified"

        blocks.append(
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*🕵️ Threat Actors:*\n{actors}"},
                    {"type": "mrkdwn", "text": f"*📋 Campaigns:*\n{campaigns}"},
                    {"type": "mrkdwn", "text": f"*📡 Source Feeds:*\n{', '.join(feeds)}"},
                    {"type": "mrkdwn", "text": f"*⚔️ ATT&CK Techniques:*\n{techniques}"},
                ],
            }
        )

        # External enrichment (VirusTotal / Shodan)
        if alert.external_enrichment:
            ext_lines = []
            emoji = {"virustotal": "🧬", "shodan": "📡"}
            for r in alert.external_enrichment[:5]:
                if not r.found:
                    continue
                icon = "🔴" if r.is_malicious() else "🟢"
                src_icon = emoji.get(r.source, "🔎")
                score = f" ({r.malicious_score}/100)" if r.malicious_score is not None else ""
                ext_lines.append(
                    f"{icon} {src_icon} *{r.source}*{score} — `{r.ioc_value}` {r.summary}"
                )
            if ext_lines:
                blocks.append(
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "*🌐 External Intel*\n" + "\n".join(ext_lines),
                        },
                    }
                )

        # Risk Score
        if alert.risk_score > 0:
            risk_bar = "█" * int(alert.risk_score / 10) + "░" * (10 - int(alert.risk_score / 10))
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*🎯 Risk Score:* `{risk_bar}` {alert.risk_score:.0f}/100",
                    },
                }
            )

        # Tags Written Back
        if alert.enrichment_tags:
            tags_text = " ".join(f"`{t}`" for t in alert.enrichment_tags[:8])
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*🏷️ Tags Written to SIEM:*\n{tags_text}",
                    },
                }
            )

        blocks.append({"type": "divider"})
        blocks.append(
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": (
                            f"🤖 threat-intel-pipeline | "
                            f"Enriched at {alert.enriched_at.strftime('%Y-%m-%d %H:%M UTC')} | "
                            f"{len(alert.extracted_iocs)} IOCs extracted, {len(alert.matched_iocs)} matched"
                        ),
                    }
                ],
            }
        )

        return {
            "text": f"🚨 TIP Alert: {alert.alert_name} [{alert.severity.upper()}] — {len(alert.matched_iocs)} IOC matches",
            "blocks": blocks,
        }

    async def notify_feed_summary(self, result: FeedIngestionResult) -> bool:
        if result.errors == 0 and result.new_iocs < 100:
            return False
        message = self.build_feed_summary(result)
        return await self.send(message)

    def build_feed_summary(self, result: FeedIngestionResult) -> dict:
        emoji = "⚠️" if result.errors > 0 else "✅"
        lines = [
            f"{emoji} *Feed Ingestion Complete: {result.feed_name}*",
            f"New IOCs: *{result.new_iocs}* | Dupes skipped: {result.duplicate_iocs} | Stored in MISP: {result.stored_in_misp}",
            f"Duration: {result.duration_seconds():.1f}s | Success rate: {result.success_rate()}%",
        ]
        if result.errors:
            lines.append(f"⚠️ *Errors: {result.errors}*")
            for err in result.error_details[:3]:
                lines.append(f"  • {err[:100]}")

        return {
            "text": f"📥 Feed: {result.feed_name} — {result.new_iocs} new IOCs, {result.errors} errors",
            "blocks": [
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": "\n".join(lines)},
                }
            ],
        }

    async def send(self, message: dict) -> bool:
        if not self.webhook_url:
            logger.debug("Slack webhook not configured — skipping notification")
            return False
        try:
            resp = await self.client.post(self.webhook_url, json=message)
            if resp.status_code == 200:
                return True
            logger.warning("Slack returned %d: %s", resp.status_code, resp.text[:200])
            return False
        except Exception as exc:
            logger.error("Slack send failed: %s", exc)
            return False

    async def health_check(self) -> bool:
        if not self.webhook_url:
            return False
        test_msg = {
            "text": "🟢 threat-intel-pipeline health check — Slack webhook operational",
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "✅ *TIP health check* — Slack integration working",
                    },
                }
            ],
        }
        return await self.send(test_msg)

    async def close(self) -> None:
        await self.client.aclose()
