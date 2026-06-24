from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator

from tip.core.timeutil import utcnow


class IOCType(str, Enum):
    IP = "ip-dst"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA256 = "sha256"
    SHA1 = "sha1"
    EMAIL = "email-src"
    FILENAME = "filename"


class ThreatLevel(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class IOC(BaseModel):
    value: str
    ioc_type: IOCType
    source_feed: str
    threat_level: ThreatLevel
    tags: list[str] = Field(default_factory=list)
    description: str = ""
    first_seen: datetime
    last_seen: datetime
    confidence: int = Field(default=50, ge=0, le=100)
    pulse_id: str | None = None
    misp_event_id: str | None = None
    misp_attribute_id: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)

    # Advanced: MITRE ATT&CK mapping
    attack_techniques: list[str] = Field(default_factory=list)
    attack_tactics: list[str] = Field(default_factory=list)

    # Threat scoring
    threat_score: float = Field(default=0.0, ge=0.0, le=100.0)

    @field_validator("confidence")
    @classmethod
    def clamp_confidence(cls, v: int) -> int:
        return max(0, min(100, v))

    def is_high_confidence(self) -> bool:
        return self.confidence >= 75

    def age_days(self) -> int:
        return (utcnow() - self.first_seen).days


class EnrichedAlert(BaseModel):
    alert_id: str
    alert_name: str
    severity: str
    source_siem: str
    triggered_at: datetime
    raw_alert: dict[str, Any] = Field(default_factory=dict)
    extracted_iocs: list[str] = Field(default_factory=list)
    matched_iocs: list[IOC] = Field(default_factory=list)
    threat_actors: list[str] = Field(default_factory=list)
    campaigns: list[str] = Field(default_factory=list)
    enrichment_tags: list[str] = Field(default_factory=list)
    enriched_at: datetime = Field(default_factory=utcnow)
    notification_sent: bool = False

    # Advanced: risk scoring
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    attack_techniques: list[str] = Field(default_factory=list)

    def has_matches(self) -> bool:
        return len(self.matched_iocs) > 0

    def highest_confidence_ioc(self) -> IOC | None:
        if not self.matched_iocs:
            return None
        return max(self.matched_iocs, key=lambda i: i.confidence)


class FeedIngestionResult(BaseModel):
    feed_name: str
    started_at: datetime
    finished_at: datetime
    total_fetched: int = 0
    new_iocs: int = 0
    duplicate_iocs: int = 0
    stored_in_misp: int = 0
    errors: int = 0
    error_details: list[str] = Field(default_factory=list)

    def duration_seconds(self) -> float:
        return (self.finished_at - self.started_at).total_seconds()

    def success_rate(self) -> float:
        if self.new_iocs == 0:
            return 0.0
        return round(self.stored_in_misp / self.new_iocs * 100, 1)


class MISPEvent(BaseModel):
    event_id: str
    title: str
    threat_level: ThreatLevel
    tags: list[str] = Field(default_factory=list)
    attribute_count: int = 0
    source_feed: str
    created_at: datetime


class IOCRelationship(BaseModel):
    """Tracks relationships between IOCs for correlation analysis."""

    source_ioc: str
    target_ioc: str
    relationship_type: str  # "resolves-to", "dropped-by", "communicates-with"
    confidence: int = 50
    source_feed: str
    first_seen: datetime


class ThreatActorProfile(BaseModel):
    """Aggregated profile for a threat actor."""

    name: str
    aliases: list[str] = Field(default_factory=list)
    description: str = ""
    motivation: str = ""
    sophistication: str = ""
    target_sectors: list[str] = Field(default_factory=list)
    attack_techniques: list[str] = Field(default_factory=list)
    ioc_count: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    source_feeds: list[str] = Field(default_factory=list)


class PipelineMetrics(BaseModel):
    """Real-time pipeline health metrics."""

    timestamp: datetime = Field(default_factory=utcnow)
    total_iocs_cached: int = 0
    iocs_by_feed: dict[str, int] = Field(default_factory=dict)
    iocs_by_type: dict[str, int] = Field(default_factory=dict)
    alerts_enriched_last_hour: int = 0
    alerts_matched_last_hour: int = 0
    notifications_sent_last_hour: int = 0
    feed_health: dict[str, bool] = Field(default_factory=dict)
    last_otx_run: datetime | None = None
    last_abusech_run: datetime | None = None
    last_enrichment_run: datetime | None = None
