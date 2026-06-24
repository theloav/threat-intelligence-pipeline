# MISP Setup Guide

Detailed configuration for the MISP instance used by this pipeline.

## Getting the API Key

1. Open MISP at [http://localhost:8080](http://localhost:8080)
2. Log in with `admin@tip.local` / `ChangeMe12345!`
3. **Administration** → **List Auth Keys**
4. Click **+ Add authentication key**
   - Comment: `threat-intel-pipeline`
   - Role: `Admin` (or create a dedicated role)
   - Expiry: leave blank for no expiry
5. Copy the generated key immediately (shown only once)
6. Set in `.env`: `TIP_MISP_API_KEY=<your-key>`

## Creating a Dedicated API User (Recommended for Production)

Instead of using the admin account:

1. **Administration** → **Add User**
   - Email: `tip-service@tip.local`
   - Role: `Sync User` or `Reporting` (depends on your needs)
   - Organisation: select your org
2. Log in as that user → generate auth key
3. Use that key instead of admin

## Configuring MISP Organisations

1. **Administration** → **Add Organisation**
   - Name: `Your Organisation`
   - UUID: auto-generated
2. Set `TIP_MISP_ORG_ID` to match the organisation ID (shown in the list)

## Setting Up Taxonomies

Taxonomies give your IOC tags structured meaning. Enable these:

1. **Event Actions** → **List Taxonomies**
2. Enable and expand:
   - **tlp** — Traffic Light Protocol (red/amber/green/white)
   - **misp-galaxy:threat-actor** — Known threat actor mapping
   - **misp-galaxy:mitre-attack-pattern** — MITRE ATT&CK
   - **malware_classification** — Malware type taxonomy

```bash
# Or via API
curl -s -H "Authorization: $TIP_MISP_API_KEY" \
  http://localhost:8080/taxonomies/enable/1 -X POST
```

## Setting Up MISP Galaxies

Galaxies provide rich threat actor context (ATT&CK techniques, threat actors, tools):

1. **Administration** → **Update Galaxy**
2. This downloads the latest MISP galaxy definitions
3. Galaxies used by this pipeline:
   - `misp-galaxy:threat-actor` — Actor attribution
   - `misp-galaxy:mitre-attack-pattern` — ATT&CK mapping

## Verifying Connectivity

```bash
# Quick connectivity test
tip status

# Or direct API test
curl -k -H "Authorization: $TIP_MISP_API_KEY" \
  http://localhost:8080/attributes/restSearch \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"returnFormat":"json","limit":1}'
```

## MISP Event Structure

This pipeline creates one MISP event per **source feed per day**:

```
otx — 2024-01-15          (all OTX IOCs from that day)
abusech_malware — 2024-01-15
abusech_url — 2024-01-15
threatfox — 2024-01-15
```

Each event contains:
- Attributes (IOC values with type and comment)
- Tags (threat actor names, TLP, malware families)
- Threat level (from TLP mapping)

## Memory Requirements

MISP Docker setup needs:

| Component | RAM |
|-----------|-----|
| MISP core | ~800 MB |
| MySQL 8   | ~400 MB |
| Redis     | ~50 MB |
| **Total** | **~1.3 GB** |

On WSL2, ensure your `.wslconfig` has sufficient memory:
```ini
[wsl2]
memory=4GB
processors=2
```

## Performance Tuning

For high-volume ingestion (>10,000 IOCs/day):

1. **MISP** → **Administration** → **Server Settings** → **MISP**
   - `MISP.background_jobs` = `true`
   - `MISP.worker_count` = `4`

2. Increase MySQL buffer pool:
   ```sql
   SET GLOBAL innodb_buffer_pool_size = 1073741824;  -- 1GB
   ```

## Backup

```bash
# Backup MISP data
docker compose -f docker/docker-compose.yml exec misp-db \
  mysqldump -u misp -pmisp-password misp > misp-backup.sql

# Restore
docker compose -f docker/docker-compose.yml exec -T misp-db \
  mysql -u misp -pmisp-password misp < misp-backup.sql
```
