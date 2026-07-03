"""
config.py — Fraud Detection & Abuse Monitoring Pipeline
Centralised thresholds, scoring weights, and SIEM/alert settings.
"""

# ── Risk score thresholds ─────────────────────────────────────────────────────
RISK_THRESHOLDS = {
    "CRITICAL": 80,   # auto-block + SIEM alert
    "HIGH":     60,   # manual review queue
    "MEDIUM":   40,   # log + monitor
    "LOW":       0,   # pass through
}

# ── Behavioural scoring weights (total = 100) ─────────────────────────────────
SCORING_WEIGHTS = {
    "login_velocity":          25,   # logins per minute
    "geo_anomaly":             20,   # impossible travel / new country
    "device_fingerprint":      15,   # new / headless browser
    "failed_auth_ratio":       15,   # failed / total attempts
    "transaction_velocity":    15,   # txns per hour
    "ip_reputation":           10,   # threat-intel score
}

# ── Detection rule limits ─────────────────────────────────────────────────────
CREDENTIAL_STUFFING = {
    "max_failed_logins_per_minute": 10,
    "max_unique_usernames_per_ip":   5,
    "lookback_seconds":             60,
}

ACCOUNT_TAKEOVER = {
    "max_password_resets_per_hour":  3,
    "max_mfa_failures_per_hour":     5,
    "impossible_travel_km_per_hour": 900,
}

PAYMENT_ANOMALY = {
    "max_txns_per_hour":             20,
    "max_txn_amount_zscore":        3.0,   # standard deviations from user mean
    "max_new_payees_per_day":         5,
}

# ── SIEM / alerting ───────────────────────────────────────────────────────────
SIEM = {
    "endpoint":    "https://your-siem-endpoint/api/events",
    "api_key_env": "SIEM_API_KEY",
    "source":      "fraud-detection-pipeline",
    "index":       "fraud_events",
}

SLACK = {
    "webhook_env": "SLACK_WEBHOOK_URL",
    "channel":     "#fraud-alerts",
}

# ── Auto-triage actions ───────────────────────────────────────────────────────
TRIAGE_ACTIONS = {
    "CRITICAL": ["block_session", "alert_siem", "alert_slack", "queue_review"],
    "HIGH":     ["flag_session",  "alert_siem", "queue_review"],
    "MEDIUM":   ["log_event",     "alert_siem"],
    "LOW":      ["log_event"],
}
