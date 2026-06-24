"""
Multi-factor threat scoring engine.

Scores are 0-100. Factors:
  - Recency (how fresh is the IOC)
  - Confidence (from source feed)
  - Source credibility (OTX pulse TLP, Abuse.ch confirmed malware)
  - Type weight (hash > IP > domain > URL for precision)
  - Tag signal (known APT/actor tags boost score)
"""

from __future__ import annotations

from datetime import datetime

from tip.core.models import IOC, IOCType, ThreatLevel
from tip.core.timeutil import utcnow

SOURCE_CREDIBILITY: dict[str, float] = {
    "abusech_malware": 95.0,  # MalwareBazaar — lab-confirmed
    "threatfox": 85.0,
    "abusech_url": 75.0,
    "otx": 65.0,  # community-contributed, variable quality
}

IOC_TYPE_WEIGHT: dict[IOCType, float] = {
    IOCType.SHA256: 1.0,
    IOCType.MD5: 0.95,
    IOCType.SHA1: 0.95,
    IOCType.IP: 0.8,
    IOCType.DOMAIN: 0.75,
    IOCType.URL: 0.7,
    IOCType.EMAIL: 0.6,
    IOCType.FILENAME: 0.5,
}

THREAT_LEVEL_MULTIPLIER: dict[ThreatLevel, float] = {
    ThreatLevel.HIGH: 1.0,
    ThreatLevel.MEDIUM: 0.75,
    ThreatLevel.LOW: 0.5,
    ThreatLevel.UNKNOWN: 0.6,
}

APT_SIGNAL_TAGS = {
    "apt",
    "apt28",
    "apt29",
    "apt30",
    "apt32",
    "apt33",
    "apt34",
    "apt38",
    "lazarus",
    "cozy bear",
    "fancy bear",
    "carbanak",
    "fin7",
    "ta505",
    "emotet",
    "trickbot",
    "ryuk",
    "darkside",
    "revil",
    "conti",
}


def compute_recency_score(ioc: IOC, now: datetime | None = None) -> float:
    """Score decays from 100 → 0 over 30 days."""
    if now is None:
        now = utcnow()
    age = (now - ioc.last_seen).total_seconds() / 3600  # hours
    if age <= 24:
        return 100.0
    if age <= 72:
        return 90.0
    if age <= 168:  # 1 week
        return 75.0
    if age <= 720:  # 30 days
        return max(0.0, 75.0 - (age - 168) / (720 - 168) * 75.0)
    return 0.0


def compute_tag_signal(ioc: IOC) -> float:
    """Boost score when tags match known APT/actor indicators."""
    lower_tags = {t.lower() for t in ioc.tags}
    matches = lower_tags & APT_SIGNAL_TAGS
    if matches:
        return min(20.0, len(matches) * 7.0)
    return 0.0


def score_ioc(ioc: IOC, weights: dict[str, float] | None = None) -> float:
    """
    Compute composite threat score 0-100.

    Default weights: recency=0.3, confidence=0.4, source=0.3
    """
    if weights is None:
        weights = {"recency": 0.3, "confidence": 0.4, "source": 0.3}

    recency = compute_recency_score(ioc)
    confidence = float(ioc.confidence)
    source = SOURCE_CREDIBILITY.get(ioc.source_feed, 60.0)

    base = (
        weights["recency"] * recency
        + weights["confidence"] * confidence
        + weights["source"] * source
    )

    # Apply type weight
    type_w = IOC_TYPE_WEIGHT.get(ioc.ioc_type, 0.6)
    base *= type_w

    # Apply threat level multiplier
    mult = THREAT_LEVEL_MULTIPLIER.get(ioc.threat_level, 0.6)
    base *= mult

    # Add APT signal boost
    base += compute_tag_signal(ioc)

    return round(min(100.0, max(0.0, base)), 2)


def score_iocs_batch(iocs: list[IOC], weights: dict[str, float] | None = None) -> list[IOC]:
    """Score a batch of IOCs and set their threat_score field."""
    for ioc in iocs:
        ioc.threat_score = score_ioc(ioc, weights)
    return sorted(iocs, key=lambda i: i.threat_score, reverse=True)
