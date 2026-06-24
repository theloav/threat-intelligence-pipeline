from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # MISP
    misp_url: str = "http://localhost:8080"
    misp_api_key: str = ""
    misp_verify_ssl: bool = False
    misp_org_id: str = "1"

    # AlienVault OTX
    otx_api_key: str = ""
    otx_base_url: str = "https://otx.alienvault.com/api/v1"
    otx_pulse_limit: int = 20
    otx_lookback_days: int = 7

    # Abuse.ch
    abusech_malware_url: str = "https://mb-api.abuse.ch/api/v1/"
    abusech_url_url: str = "https://urlhaus-api.abuse.ch/v1/"
    abusech_threatfox_url: str = "https://threatfox-api.abuse.ch/api/v1/"
    abusech_lookback_days: int = 1

    # Dedup cache
    cache_backend: str = "sqlite"
    cache_sqlite_path: str = "./cache/dedup.db"
    redis_url: str = "redis://localhost:6379/0"
    cache_ttl_days: int = 30

    # Microsoft Sentinel
    sentinel_subscription_id: str = ""
    sentinel_resource_group: str = ""
    sentinel_workspace_name: str = ""
    sentinel_token: str = ""

    # Elastic
    elastic_url: str = "http://localhost:9200"
    elastic_username: str = "elastic"
    elastic_password: str = "changeme"
    elastic_kibana_url: str = "http://localhost:5601"
    elastic_alerts_index: str = ".alerts-security.alerts-default"

    # Slack
    slack_webhook_url: str = ""
    slack_channel: str = "#threat-intel"
    slack_notify_on: list[str] = ["high", "critical"]

    # Scheduler
    otx_schedule_minutes: int = 60
    abusech_schedule_minutes: int = 15
    enrichment_schedule_minutes: int = 5

    # Advanced: STIX export
    stix_export_enabled: bool = False
    stix_export_path: str = "./exports/stix"

    # Advanced: Prometheus metrics
    metrics_enabled: bool = False
    metrics_port: int = 9090

    # Advanced: Threat scoring weights
    scoring_recency_weight: float = 0.3
    scoring_confidence_weight: float = 0.4
    scoring_source_weight: float = 0.3

    # API server (optional FastAPI dashboard)
    api_enabled: bool = False
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_secret_key: str = "change-me-in-production"

    model_config = SettingsConfigDict(env_file=".env", env_prefix="TIP_", extra="ignore")


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
