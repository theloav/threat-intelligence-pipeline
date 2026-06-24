# threat-intel-pipeline

> Full threat intelligence lifecycle: **OTX + Abuse.ch → MISP → enrich Sentinel/Elastic alerts → Slack IOC context.**

[![CI](https://github.com/theloav/threat-intelligence-pipeline/actions/workflows/test.yml/badge.svg)](https://github.com/theloav/threat-intelligence-pipeline/actions/workflows/test.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://python.org)
[![Feeds](https://img.shields.io/badge/feeds-3%20(OTX%20%2B%20MalwareBazaar%20%2B%20URLhaus%20%2B%20ThreatFox)-orange)](docs/adding-a-feed.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## What this demonstrates

1. **Ingest** — Pull fresh IOCs from AlienVault OTX (subscribed pulses) and three Abuse.ch APIs (MalwareBazaar, URLhaus, ThreatFox) on configurable schedules
2. **Normalise** — Validate and clean IOCs: strip private IPs, deduplicate hashes, lowercase domains, remove junk
3. **Store** — Deduplicate against SQLite/Redis cache; push net-new IOCs into self-hosted MISP with per-feed-per-day events and full tagging
4. **Enrich** — Query MISP for IOC matches in Microsoft Sentinel and Elastic Security alerts; write enrichment tags back to the SIEM
5. **Notify** — Send Slack Block Kit messages with full threat actor attribution, MITRE ATT&CK techniques, risk scores, and tags written back

---

## Quick start

```bash
# 1. Clone
git clone https://github.com/theloav/threat-intelligence-pipeline
cd threat-intelligence-pipeline

# 2. Configure
cp .env.example .env
# Edit .env: set TIP_OTX_API_KEY and TIP_MISP_API_KEY (see docs/setup.md)

# 3. Start MISP (takes ~90 seconds on first boot)
docker compose -f docker/docker-compose.yml up -d misp misp-db misp-redis

# 4. Install
pip install -e ".[dev]"

# 5. Health check (retry 5x while MISP starts)
tip status --retry 5

# 6. Run all tests (no Docker/API keys needed)
pytest tests/ -v

# 7. First feed ingestion
tip feeds run

# 8. Look up an IOC
tip lookup 185.220.101.5

# 9. Full pipeline
tip run
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    COLLECTION LAYER                          │
│  ┌──────────────┐  ┌─────────────────────────────────────┐  │
│  │ AlienVault   │  │         Abuse.ch (3 APIs)           │  │
│  │ OTX Pulses   │  │ MalwareBazaar │ URLhaus │ ThreatFox │  │
│  └──────┬───────┘  └────────────────┬────────────────────┘  │
└─────────┼──────────────────────────┼───────────────────────┘
          │                          │
          ▼                          ▼
┌─────────────────────────────────────────────────────────────┐
│                  NORMALISATION LAYER                         │
│  IOCNormaliser: validate IPs, strip private ranges,         │
│  lowercase domains, validate hash lengths, dedup by value   │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│               DEDUP CACHE (SQLite / Redis)                  │
│  (value, ioc_type) → expires_at                             │
│  Skip IOCs already stored within TTL window                 │
└─────────────────────────┬───────────────────────────────────┘
                          │ net-new only
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                  MISP (self-hosted)                         │
│  Events: "{source_feed} — {date}"                           │
│  Attributes: IOC values with type, comment, to_ids=True     │
│  Tags: threat actors, TLP, malware families, ATT&CK         │
└─────────────────────────┬───────────────────────────────────┘
                          │ lookup
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                  ENRICHMENT LAYER                           │
│  Extract IOC values from Elastic / Sentinel alerts          │
│  Bulk lookup in MISP → matched attributes + context         │
│  Write enrichment tags back to SIEM                         │
│  Multi-factor threat scoring (0–100)                        │
└─────────────────────────┬───────────────────────────────────┘
                          │ high-severity matches
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                  NOTIFICATION LAYER                         │
│  Slack Block Kit: alert details, IOC matches (max 5),       │
│  threat actors, ATT&CK techniques, risk score, tags          │
└─────────────────────────────────────────────────────────────┘
```

---

## Feeds

| Feed | Source | IOC Types | Update Interval | API Key |
|------|--------|-----------|-----------------|---------|
| OTX Subscribed Pulses | AlienVault OTX | IP, Domain, URL, MD5, SHA256, SHA1, Email | 60 min | Required (free) |
| MalwareBazaar | Abuse.ch | SHA256, MD5, Filename | 15 min | None |
| URLhaus | Abuse.ch | URL, Domain/IP | 15 min | None |
| ThreatFox | Abuse.ch | IP, Domain, URL, MD5, SHA256 | 15 min | None |

---

## CLI reference

```
tip run                        Full pipeline (ingest + enrich + notify)
tip feeds run [--feed otx|abusech|all]
tip feeds status               Feed health + cache stats
tip enrich [--siem elastic|sentinel|all]
tip lookup VALUE               Look up IOC in MISP
tip scheduler                  Start continuous scheduler (blocks)
tip status [--retry N]         Health check all services
tip cache stats                Show dedup cache stats
tip cache purge                Remove expired cache entries
```

---

## Example Slack notification

```json
{
  "blocks": [
    { "type": "header", "text": "🚨 ALERT: Suspicious Outbound Connection" },
    {
      "type": "section",
      "fields": [
        "*Severity:* 🟠 HIGH",
        "*Source SIEM:* 🔍 Elastic",
        "*Alert ID:* `alert-00af12`",
        "*Triggered:* 2024-01-15 10:23 UTC"
      ]
    },
    { "type": "divider" },
    {
      "type": "section",
      "text": "🎯 IOC Matches (3 found)\n🔴 `ip-dst` *185.220.101.5* — TOR exit node, used by APT28 for C2\n🔴 `domain` *update-cdn.evil.ru* — Dropper domain\n🟡 `sha256` *3c9bf...* — CobaltStrike beacon"
    },
    {
      "type": "section",
      "fields": [
        "*🕵️ Threat Actors:* APT28, Fancy Bear",
        "*📋 Campaigns:* Operation Groundbait",
        "*📡 Source Feeds:* otx, threatfox",
        "*⚔️ ATT&CK:* T1071, T1059, T1027"
      ]
    },
    {
      "type": "section",
      "text": "*🎯 Risk Score:* `████████░░` 82/100"
    },
    {
      "type": "section",
      "text": "*🏷️ Tags Written to SIEM:*\n`tip:matched` `tip:feed:otx` `tip:actor:APT28` `tip:ioc-type:ip-dst` `tip:attack:T1071`"
    }
  ]
}
```

---

## Advanced features

### Multi-factor threat scoring
Every matched IOC gets a 0–100 score based on:
- **Recency** (30%): IOCs from the last 24h score highest
- **Confidence** (40%): Source-reported confidence level
- **Source credibility** (30%): MalwareBazaar (lab-confirmed) > ThreatFox > OTX

Configurable weights via `.env`:
```bash
TIP_SCORING_RECENCY_WEIGHT=0.3
TIP_SCORING_CONFIDENCE_WEIGHT=0.4
TIP_SCORING_SOURCE_WEIGHT=0.3
```

### Optional Elasticsearch enrichment

```bash
docker compose -f docker/docker-compose.yml --profile elastic up -d
tip enrich --siem elastic
```

### Redis dedup cache (production)

```bash
TIP_CACHE_BACKEND=redis
TIP_REDIS_URL=redis://localhost:6379/0
```

---

## Extending

See **[docs/adding-a-feed.md](docs/adding-a-feed.md)** for a complete walkthrough with a working CSV feed example.

Key extension points:
- **New feed:** subclass `BaseFeed`, implement `fetch()` and `health_check()`
- **New SIEM:** implement `get_alerts()`, `update_alert()`, `health_check()`
- **New notifier:** follow the `send(message: dict) → bool` pattern

---

## Lab setup notes

> MISP requires ~1.3 GB RAM total (core + MySQL + Redis). On a laptop, this is fine alongside other containers. On WSL2, set `memory=4GB` in `.wslconfig`.

> MISP takes **60–90 seconds** to start on first boot (database schema creation). Subsequent starts are fast. Use `tip status --retry 5` to wait automatically.

> All tests pass without Docker or real API keys: `pytest tests/ -v`

---

## Project structure

```
tip/
├── core/          models, config, threat scoring engine
├── feeds/         OTX + Abuse.ch collectors, APScheduler scheduler
├── misp/          PyMISP client, IOC normaliser, SQLite/Redis dedup cache
├── enrichment/    MISP lookup engine, alert enricher, SIEM tag writer
├── siem/          Elastic Security + Microsoft Sentinel clients
├── notification/  Slack Block Kit notifier
└── cli.py         Click CLI (tip run, tip feeds, tip lookup, ...)
```
