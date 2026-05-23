# Threat Intelligence Platform (TIP) & Dynamic Policy Enforcer
**Infotact Internship — Project 1: Finance & Banking**

---

## Architecture

```
OSINT Feeds (OTX, VirusTotal, Abuse.ch, URLhaus)
        ↓
  fetchers.py  →  risk_scorer.py  →  MongoDB
        ↓                                ↓
  main.py (scheduler)          siem_sync.py → Elasticsearch → Kibana
                                             ↓
                                       enforcer.py → iptables DROP
```

---

## Project Structure

```
tip_project/
├── main.py                  # Master pipeline runner
├── requirements.txt
├── .env.example             # Copy to .env and fill API keys
├── .gitignore
├── src/
│   ├── config.py            # Loads all env vars
│   ├── database.py          # MongoDB operations
│   ├── fetchers.py          # OSINT feed scrapers
│   ├── risk_scorer.py       # Threat scoring engine
│   ├── siem_sync.py         # MongoDB → Elasticsearch sync
│   ├── enforcer.py          # iptables policy daemon
│   └── alerter.py           # Slack + email alerts
├── tests/
│   └── test_project.py      # Unit tests
├── docker/
│   └── docker-compose.yml   # MongoDB + ELK Stack
└── docs/
    └── architecture.md
```

---

## Setup

### 1. Prerequisites
- Ubuntu 20.04+ (or WSL2) with Python 3.10+
- Docker & Docker Compose
- `sudo` access for iptables commands

### 2. Clone & Install
```bash
git clone https://github.com/YOUR_USERNAME/tip-project.git
cd tip-project
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Configure API Keys
```bash
cp .env.example .env
nano .env   # fill in your API keys
```
- AlienVault OTX key: https://otx.alienvault.com/api
- VirusTotal key: https://www.virustotal.com/gui/my-apikey

### 4. Start Infrastructure
```bash
cd docker
docker compose up -d
# Wait ~30 seconds for Elasticsearch to start
```

### 5. Initialize Database
```bash
python main.py --setup
```

---

## Usage

### Run the full pipeline once
```bash
python main.py
```

### Run on hourly schedule (leave running)
```bash
python main.py --schedule
```

### Start the enforcement daemon (requires sudo)
```bash
sudo python -m src.enforcer
```

### Run one enforcement cycle
```bash
sudo python -m src.enforcer --once
```

### Unblock a specific IP
```bash
sudo python -m src.enforcer --rollback 1.2.3.4
```

### Full iptables rollback to last snapshot
```bash
sudo python -m src.enforcer --rollback-all
```

### View currently blocked IPs
```bash
python -m src.enforcer --list
```

### Run tests
```bash
pytest tests/ -v
```

---

## Kibana Dashboard Setup

1. Open http://localhost:5601
2. Go to **Stack Management → Index Patterns**
3. Create pattern: `threat_indicators`
4. Build visualizations:
   - Pie chart: `type` field (IP vs Domain vs Hash)
   - Bar chart: `source` field (feed distribution)
   - Metric: `risk_score` average
   - Table: top 20 by `risk_score` descending
   - Filter by `blocked: true` for enforcement view

---

## Risk Scoring

| Source         | Base Score |
|----------------|-----------|
| VirusTotal     | 30        |
| AlienVault OTX | 25        |
| Abuse.ch       | 22        |
| Feodo Tracker  | 18        |
| URLhaus        | 15        |

| Type    | Score |
|---------|-------|
| IP      | +40   |
| URL     | +30   |
| Domain  | +35   |
| Hash    | +25   |

High-risk tags (`malware`, `ransomware`, `botnet`, `c2`, `apt`) add +5 each (max +25).
Corroboration (seen in multiple feeds) adds +5 per extra feed (max +15).

---

## Security Notes

- **Never** hardcode API keys — use `.env` file only
- `.env` is in `.gitignore` — it will never be committed
- All sensitive data injected via environment variables
- iptables rules are snapshotted before every enforcement batch
- Rollback is always available via `--rollback` or `--rollback-all`

---

## GitHub Commit Convention

```
feat: add VirusTotal IP reputation fetcher
fix: resolve MongoDB duplicate key error on upsert
docs: update README with Kibana dashboard setup
test: add unit tests for risk_scorer batch function
refactor: extract IP validation to shared helper
```

---

## Compliance

This project supports **PCI-DSS** compliance by:
- Maintaining immutable audit logs of all block/unblock events
- Providing real-time threat intelligence dashboards
- Automating network access control list (ACL) enforcement
- Enabling rollback for false positive remediation
