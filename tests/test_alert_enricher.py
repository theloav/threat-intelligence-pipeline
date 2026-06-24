"""Tests for AlertEnricher — mocks MISPLookup, TagWriter, SlackNotifier."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from tip.core.models import IOC, IOCType, ThreatLevel
from tip.enrichment.alert_enricher import AlertEnricher


def _now():
    """Naive-UTC now for test fixtures."""
    return datetime.now(UTC).replace(tzinfo=None)


def _ioc(value="1.2.3.4", tags=None, attack_techniques=None) -> IOC:
    return IOC(
        value=value,
        ioc_type=IOCType.IP,
        source_feed="otx",
        threat_level=ThreatLevel.HIGH,
        tags=tags or ["threat-actor:APT28"],
        description="Test IOC",
        first_seen=_now(),
        last_seen=_now(),
        confidence=80,
        attack_techniques=attack_techniques or ["T1071"],
    )


def _make_enricher(
    matched_iocs=None,
    notify_on=None,
    tag_write_result=True,
    slack_result=True,
    external_manager=None,
    enrich_unmatched=False,
):
    misp_lookup = MagicMock()
    misp_lookup.extract_iocs_from_alert = MagicMock(return_value=["1.2.3.4", "evil.com"])
    misp_lookup.lookup_alert_iocs = AsyncMock(return_value=matched_iocs or [])

    tag_writer = MagicMock()
    tag_writer.build_enrichment_tags = MagicMock(return_value=["tip:matched", "tip:feed:otx"])
    tag_writer.write_tags = AsyncMock(return_value=tag_write_result)

    slack = MagicMock()
    slack.notify_enriched_alert = AsyncMock(return_value=slack_result)

    enricher = AlertEnricher(
        misp_lookup=misp_lookup,
        tag_writer=tag_writer,
        sentinel_client=None,
        elastic_client=None,
        slack_notifier=slack,
        notify_on=notify_on or ["high", "critical"],
        external_manager=external_manager,
        enrich_unmatched=enrich_unmatched,
    )
    return enricher, misp_lookup, tag_writer, slack


def _alert(severity="high") -> dict:
    return {
        "_id": "alert-001",
        "_source": {
            "kibana.alert.rule.name": "Suspicious IP",
            "severity": severity,
            "source.ip": "1.2.3.4",
            "@timestamp": "2024-01-15T10:00:00Z",
        },
    }


@pytest.mark.asyncio
async def test_enrich_alert_with_match_calls_tag_writer():
    ioc = _ioc()
    enricher, _, tag_writer, _ = _make_enricher(matched_iocs=[ioc])

    result = await enricher.enrich_alert(_alert(), "elastic")

    tag_writer.build_enrichment_tags.assert_called_once_with([ioc])
    tag_writer.write_tags.assert_called_once()
    assert "tip:matched" in result.enrichment_tags


@pytest.mark.asyncio
async def test_enrich_alert_no_match_does_not_notify():
    enricher, _, _, slack = _make_enricher(matched_iocs=[])

    result = await enricher.enrich_alert(_alert(), "elastic")

    slack.notify_enriched_alert.assert_not_called()
    assert result.notification_sent is False
    assert result.matched_iocs == []


@pytest.mark.asyncio
async def test_enrich_alert_with_match_calls_slack():
    ioc = _ioc()
    enricher, _, _, slack = _make_enricher(matched_iocs=[ioc])

    result = await enricher.enrich_alert(_alert(severity="high"), "elastic")

    slack.notify_enriched_alert.assert_called_once()
    assert result.notification_sent is True


@pytest.mark.asyncio
async def test_enriched_alert_has_correct_threat_actors():
    ioc1 = _ioc(tags=["threat-actor:APT28", "malware"])
    ioc2 = _ioc(value="evil.com", tags=["threat-actor:Lazarus"])
    enricher, _, _, _ = _make_enricher(matched_iocs=[ioc1, ioc2])

    result = await enricher.enrich_alert(_alert(), "elastic")

    assert "APT28" in result.threat_actors
    assert "Lazarus" in result.threat_actors


@pytest.mark.asyncio
async def test_low_severity_does_not_trigger_slack():
    ioc = _ioc()
    enricher, _, _, slack = _make_enricher(
        matched_iocs=[ioc],
        notify_on=["high", "critical"],
    )

    result = await enricher.enrich_alert(_alert(severity="low"), "elastic")

    slack.notify_enriched_alert.assert_not_called()
    assert result.notification_sent is False


@pytest.mark.asyncio
async def test_attack_techniques_propagated():
    ioc = _ioc(attack_techniques=["T1071", "T1059"])
    enricher, _, _, _ = _make_enricher(matched_iocs=[ioc])

    result = await enricher.enrich_alert(_alert(), "elastic")

    assert "T1071" in result.attack_techniques
    assert "T1059" in result.attack_techniques


@pytest.mark.asyncio
async def test_enrichment_returns_extracted_ioc_list():
    enricher, misp_lookup, _, _ = _make_enricher(matched_iocs=[])

    result = await enricher.enrich_alert(_alert(), "elastic")

    assert "1.2.3.4" in result.extracted_iocs
    assert "evil.com" in result.extracted_iocs


@pytest.mark.asyncio
async def test_tag_writer_failure_does_not_crash_enrichment():
    """Tag write failure should be swallowed, enrichment still completes."""
    ioc = _ioc()
    enricher, _, tag_writer, _ = _make_enricher(
        matched_iocs=[ioc],
        tag_write_result=False,
    )
    tag_writer.write_tags = AsyncMock(side_effect=Exception("network error"))

    # Should not raise
    result = await enricher.enrich_alert(_alert(), "elastic")
    assert result is not None
    assert result.matched_iocs == [ioc]


@pytest.mark.asyncio
async def test_external_enrichment_attached_and_scores_risk():
    """VT/Shodan results are attached and boost the alert risk score."""
    from tip.core.models import ExternalEnrichmentResult

    manager = MagicMock()
    manager.active = True
    manager.enrich_iocs = AsyncMock(
        return_value=[
            ExternalEnrichmentResult(
                source="virustotal",
                ioc_value="1.2.3.4",
                found=True,
                malicious_score=90,
                summary="45/70 engines flagged malicious",
            )
        ]
    )
    ioc = _ioc()
    enricher, _, _, _ = _make_enricher(matched_iocs=[ioc], external_manager=manager)

    result = await enricher.enrich_alert(_alert(), "elastic")

    assert len(result.external_enrichment) == 1
    assert result.external_enrichment[0].source == "virustotal"
    assert result.risk_score >= 90  # external verdict raised the score
    assert "tip:virustotal:malicious" in result.enrichment_tags


@pytest.mark.asyncio
async def test_external_malicious_triggers_notify_without_misp_match():
    """Even with no MISP match, an external malicious verdict notifies."""
    from tip.core.models import ExternalEnrichmentResult

    manager = MagicMock()
    manager.active = True
    manager.enrich_iocs = AsyncMock(return_value=[])
    manager.enrich_value = AsyncMock(
        return_value=[
            ExternalEnrichmentResult(
                source="shodan",
                ioc_value="1.2.3.4",
                found=True,
                malicious_score=85,
                summary="malware tag",
            )
        ]
    )
    enricher, _, _, slack = _make_enricher(
        matched_iocs=[], external_manager=manager, enrich_unmatched=True
    )

    result = await enricher.enrich_alert(_alert(severity="high"), "elastic")

    slack.notify_enriched_alert.assert_called_once()
    assert result.notification_sent is True
