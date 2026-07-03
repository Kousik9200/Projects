# Fraud Detection & Real-time Abuse Monitoring Pipeline

Automated fraud detection pipeline using Python and behavioral analytics to identify **credential stuffing**, **account takeover (ATO)**, and **anomalous payment activity** in real time. Integrates with SIEM for live alerting; a behavioral scoring engine flags high-risk sessions with configurable thresholds and auto-triage workflows.

---

## Architecture

```
Event Stream
     │
     ▼
BehaviouralScorer          ← 6-dimension risk scoring (0–100 per dimension)
     │
     ▼
classify_risk()            ← CRITICAL / HIGH / MEDIUM / LOW
     │
     ▼
triage()                   ← dispatches actions per risk level
  ├── block_session
  ├── alert_siem            ← POST to SIEM ingest endpoint
  ├── alert_slack           ← Slack webhook notification
  └── queue_review          ← manual review flag
```

---

## Scoring Dimensions

| Dimension | Weight | Signal |
|---|---|---|
| Login velocity | 25% | Logins/min from same IP |
| Geo anomaly | 20% | Impossible travel, new country |
| Device fingerprint | 15% | New device, headless browser, Tor |
| Failed auth ratio | 15% | Failed / total auth attempts |
| Transaction velocity | 15% | Txns/hr + amount z-score |
| IP reputation | 10% | Threat-intel score (0–100) |

---

## Detection Rules

**Credential Stuffing**
- > 10 failed logins/min from same IP
- > 5 unique usernames per IP in 60 s

**Account Takeover**
- > 3 password resets/hr
- > 5 MFA failures/hr
- Impossible travel (> 900 km/h between logins)

**Payment Anomaly**
- > 20 transactions/hr
- Amount z-score > 3.0 (3 std devs from user baseline)
- > 5 new payees added in 24 h

---

## Auto-triage Actions

| Risk Level | Score | Actions |
|---|---|---|
| CRITICAL | ≥ 80 | block session · SIEM alert · Slack alert · queue review |
| HIGH | ≥ 60 | flag session · SIEM alert · queue review |
| MEDIUM | ≥ 40 | log event · SIEM alert |
| LOW | < 40 | log event |

---

## Quick Start

```bash
# Run real-time stream simulation (30 seconds)
python fraud_detector.py --stream

# Process a single event file
python fraud_detector.py --event event.json
```

**Example event JSON:**
```json
{
  "session_id": "abc-123",
  "user_id": "user_4521",
  "ip_address": "203.0.113.42",
  "new_device": true,
  "new_country": false,
  "headless_browser": true,
  "tor_exit_node": false,
  "ip_reputation_score": 72,
  "history": {
    "logins_per_minute": 15,
    "travel_speed_kmh": 0,
    "failed_auth_attempts": 12,
    "total_auth_attempts": 14,
    "txns_per_hour": 22,
    "amount_zscore": 4.1
  }
}
```

---

## Configuration

Edit `config.py` to tune:
- `RISK_THRESHOLDS` — score cutoffs per risk level
- `SCORING_WEIGHTS` — dimension weights (must sum to 100)
- `SIEM` / `SLACK` — endpoint and auth settings
- `TRIAGE_ACTIONS` — actions per risk level

Set environment variables before running:
```bash
export SIEM_API_KEY="your-key"
export SLACK_WEBHOOK_URL="https://hooks.slack.com/..."
```

---

## Files

| File | Purpose |
|---|---|
| `fraud_detector.py` | Main pipeline orchestrator |
| `behavioral_scorer.py` | 6-dimension behavioural scoring engine |
| `siem_integration.py` | SIEM and Slack alerting client |
| `config.py` | Thresholds, weights, and integration settings |
| `.github/workflows/fraud-detection.yml` | CI/CD: runs stream simulation every 5 min |

---

*Part of the portfolio of Kousik Gunasekaran — Cybersecurity Engineer*
