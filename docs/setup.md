# Setup Guide

This guide takes you from zero to a fully operational threat intelligence pipeline in under 15 minutes.

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Docker + Docker Compose | v2.x | `docker compose` (not `docker-compose`) |
| Python | 3.11+ | `python --version` |
| OTX API key | Free | [otx.alienvault.com](https://otx.alienvault.com) — 2 min signup |
| Slack webhook | Free | Only needed for notifications |

> **Memory:** MISP needs ~2 GB RAM. On WSL2, set `memory=4GB` in `.wslconfig`.

---

## Step 1: Clone and configure

```bash
git clone https://github.com/theloav/threat-intelligence-pipeline
cd threat-intelligence-pipeline

cp .env.example .env
```

Edit `.env` — minimum required fields:

```bash
TIP_OTX_API_KEY=your-key-from-otx.alienvault.com
TIP_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...  # optional
```

---

## Step 2: Start MISP

```bash
docker compose -f docker/docker-compose.yml up -d misp misp-db misp-redis
```

**MISP takes 60–90 seconds to initialise.** Watch it:

```bash
docker compose -f docker/docker-compose.yml logs -f misp
# Wait for: "MISP is ready"
```

Or just wait 90 seconds and run `tip status`.

---

## Step 3: Get the MISP API key

1. Open [http://localhost:8080](http://localhost:8080)
2. Login: `admin@tip.local` / `ChangeMe12345!`
3. Navigate to: **Administration → List Auth Keys**
4. Copy the API key and add to `.env`:

```bash
TIP_MISP_API_KEY=your-api-key-here
```

> First-time setup: MISP will prompt you to change the admin password on first login.

---

## Step 4: Get your OTX API key

1. Create a free account at [otx.alienvault.com](https://otx.alienvault.com)
2. Go to **My Settings** → scroll down to **OTX Key**
3. Copy the 64-character key to `.env`

No subscriptions needed — the free tier gives you 10,000 API requests/hour, which is plenty.

---

## Step 5: Configure Slack (optional but recommended)

1. Go to [api.slack.com/apps](https://api.slack.com/apps) → **Create New App**
2. Choose **From scratch** → name it `threat-intel-pipeline`
3. **Incoming Webhooks** → Enable → Add New Webhook → select `#threat-intel`
4. Copy the webhook URL to `.env`:

```bash
TIP_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T.../B.../...
TIP_SLACK_NOTIFY_ON=["high","critical"]
```

---

## Step 6: Install the pipeline

```bash
pip install -e ".[dev]"
```

---

## Step 7: Verify everything is working

```bash
tip status
```

Expected output:
```
Service         Status    Note
─────────────────────────────────────────────
MISP            ✅ OK    http://localhost:8080
AlienVault OTX  ✅ OK    API key configured
Abuse.ch        ✅ OK    No API key needed
Elasticsearch   ⚪ N/A   Not configured (optional)
Microsoft Sentinel ⚪ N/A  Not configured (optional)
Slack           ✅ OK    Webhook working
```

---

## Step 8: First ingestion

```bash
# Run all feeds once
tip feeds run

# Or just OTX
tip feeds run --feed otx

# Or just Abuse.ch (no API key needed)
tip feeds run --feed abusech
```

---

## Step 9: Test MISP lookup

```bash
tip lookup 8.8.8.8           # public IP — probably not in MISP
tip lookup evil.example.com  # domain
tip lookup <sha256-hash>     # file hash
```

---

## Step 10: Full pipeline run

```bash
tip run
```

This: ingests all feeds → enriches SIEM alerts → sends Slack notifications.

---

## Step 11: Start the continuous scheduler

```bash
tip scheduler
```

Runs OTX every 60 minutes, Abuse.ch every 15 minutes. Press `Ctrl+C` to stop.

---

## Optional: Start Elasticsearch for demo enrichment

```bash
docker compose -f docker/docker-compose.yml --profile elastic up -d
```

Then update `.env`:
```bash
TIP_ELASTIC_URL=http://localhost:9200
```

---

## Troubleshooting

### MISP returns 401
- Double-check `TIP_MISP_API_KEY` — it's the hex key from **Administration → Auth Keys**, not your login password
- Ensure MISP has fully started (check with `docker logs` — wait for "ready")

### OTX returns 403
- Check `TIP_OTX_API_KEY` is the 64-char key, not your password
- Try: `curl -H "X-OTX-API-KEY: $TIP_OTX_API_KEY" https://otx.alienvault.com/api/v1/user/me`

### MISP takes forever to start
- MISP genuinely takes 60–90 seconds on first boot (database schema creation)
- On subsequent starts it's much faster
- Run `tip status --retry 5` to auto-retry

### "Connection refused" for MISP
- Check Docker is running: `docker ps | grep misp`
- Check port: `curl http://localhost:8080`
- MISP logs: `docker compose -f docker/docker-compose.yml logs misp`

### Cache errors
```bash
mkdir -p cache
tip cache stats
```

### Tests failing
```bash
pip install -e ".[dev]"
pytest tests/ -v  # no Docker or API keys needed
```
