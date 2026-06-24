"""Tests for SlackNotifier — mocked with respx."""
from __future__ import annotations

from datetime import datetime
from unittest.mock import MagicMock

import pytest
import respx
import httpx

from tip.core.config import Settings
from tip.core.models import EnrichedAlert, FeedIngestionResult, IOC, IOCType, ThreatLevel
from tip.notification.slack_notifier import SlackNotifier


def _settings(webhook="https://hooks.slack.com/test/webhook", notify_on=None) -> Settings:
    return Settings(
        misp_api_key="x",
        slack_webhook_url=webhook,
        slack_notify_on=notify_on or ["high", "critical"],
    )


def _ioc(value="1.2.3.4") -> IOC:
    return IOC(
        value=value,
        ioc_type=IOCType.IP,
        source_feed="otx",
        threat_level=ThreatLevel.HIGH,
        tags=["threat-actor:APT28"],
        description="C2 server used by APT28",
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow(),
        confidence=85,
        threat_score=82.0,
        attack_techniques=["T1071"],
    )


def _alert(severity="high", matched=True) -> EnrichedAlert:
    iocs = [_ioc()] if matched else []
    return EnrichedAlert(
        alert_id="alert-001",
        alert_name="Suspicious Outbound Connection",
        severity=severity,
        source_siem="elastic",
        triggered_at=datetime.utcnow(),
        matched_iocs=iocs,
        threat_actors=["APT28"] if matched else [],
        campaigns=[],
        enrichment_tags=["tip:matched", "tip:feed:otx", "tip:actor:APT28"],
        attack_techniques=["T1071"] if matched else [],
        risk_score=82.0 if matched else 0.0,
    )


def _feed_result(errors=0, new_iocs=10) -> FeedIngestionResult:
    return FeedIngestionResult(
        feed_name="otx",
        started_at=datetime.utcnow(),
        finished_at=datetime.utcnow(),
        total_fetched=new_iocs,
        new_iocs=new_iocs,
        duplicate_iocs=0,
        stored_in_misp=new_iocs,
        errors=errors,
        error_details=["connection timeout"] if errors else [],
    )


def test_build_message_has_required_blocks():
    notifier = SlackNotifier(_settings())
    alert = _alert()
    message = notifier.build_message(alert)

    assert "blocks" in message
    block_types = [b["type"] for b in message["blocks"]]
    assert "header" in block_types
    assert "section" in block_types
    assert "divider" in block_types
    assert "context" in block_types


def test_build_message_header_contains_alert_name():
    notifier = SlackNotifier(_settings())
    alert = _alert()
    message = notifier.build_message(alert)

    header = message["blocks"][0]
    assert header["type"] == "header"
    assert "Suspicious Outbound Connection" in header["text"]["text"]


def test_build_message_contains_ioc_values():
    notifier = SlackNotifier(_settings())
    alert = _alert()
    message = notifier.build_message(alert)

    text_content = str(message)
    assert "1.2.3.4" in text_content


def test_build_message_contains_threat_actor():
    notifier = SlackNotifier(_settings())
    alert = _alert()
    message = notifier.build_message(alert)

    text_content = str(message)
    assert "APT28" in text_content


@pytest.mark.asyncio
async def test_send_returns_true_on_200():
    notifier = SlackNotifier(_settings())
    with respx.mock:
        respx.post("https://hooks.slack.com/test/webhook").mock(
            return_value=httpx.Response(200, text="ok")
        )
        result = await notifier.send({"text": "test"})
    assert result is True
    await notifier.close()


@pytest.mark.asyncio
async def test_send_returns_false_on_error():
    notifier = SlackNotifier(_settings())
    with respx.mock:
        respx.post("https://hooks.slack.com/test/webhook").mock(
            return_value=httpx.Response(500, text="Internal Server Error")
        )
        result = await notifier.send({"text": "test"})
    assert result is False
    await notifier.close()


@pytest.mark.asyncio
async def test_send_returns_false_on_network_error():
    notifier = SlackNotifier(_settings())
    with respx.mock:
        respx.post("https://hooks.slack.com/test/webhook").mock(
            side_effect=httpx.ConnectError("connection refused")
        )
        result = await notifier.send({"text": "test"})
    assert result is False
    await notifier.close()


@pytest.mark.asyncio
async def test_low_severity_alert_not_notified():
    """severity='low', notify_on=['high'] → not sent."""
    notifier = SlackNotifier(_settings(notify_on=["high", "critical"]))
    alert = _alert(severity="low")

    with respx.mock:
        # Should not make any HTTP call
        result = await notifier.notify_enriched_alert(alert)

    assert result is False


@pytest.mark.asyncio
async def test_high_severity_alert_is_notified():
    notifier = SlackNotifier(_settings(notify_on=["high"]))
    alert = _alert(severity="high")

    with respx.mock:
        respx.post("https://hooks.slack.com/test/webhook").mock(
            return_value=httpx.Response(200, text="ok")
        )
        result = await notifier.notify_enriched_alert(alert)

    assert result is True
    await notifier.close()


@pytest.mark.asyncio
async def test_feed_summary_sent_on_errors():
    """errors > 0 → notification sent."""
    notifier = SlackNotifier(_settings())
    result_obj = _feed_result(errors=3, new_iocs=5)

    with respx.mock:
        respx.post("https://hooks.slack.com/test/webhook").mock(
            return_value=httpx.Response(200, text="ok")
        )
        result = await notifier.notify_feed_summary(result_obj)

    assert result is True
    await notifier.close()


@pytest.mark.asyncio
async def test_feed_summary_not_sent_when_no_errors_few_iocs():
    """No errors and < 100 new IOCs → no notification."""
    notifier = SlackNotifier(_settings())
    result_obj = _feed_result(errors=0, new_iocs=50)

    with respx.mock:
        result = await notifier.notify_feed_summary(result_obj)

    assert result is False


@pytest.mark.asyncio
async def test_no_webhook_configured_returns_false():
    notifier = SlackNotifier(_settings(webhook=""))
    result = await notifier.send({"text": "test"})
    assert result is False


def test_build_feed_summary_contains_feed_name():
    notifier = SlackNotifier(_settings())
    result_obj = _feed_result(errors=1, new_iocs=5)
    msg = notifier.build_feed_summary(result_obj)
    assert "otx" in str(msg)
