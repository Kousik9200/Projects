#!/usr/bin/env python3
"""
LAB 7: Zero Trust & Network Security
======================================
Objective: Design, validate, and simulate enforcement of a Zero Trust
network architecture. Covers microsegmentation, mTLS policy design,
identity-aware access control, and east-west lateral movement prevention.

Simulated environment — no live network required.
Author: Kousik Gunasekaran
"""

import json
import ipaddress
from datetime import datetime, timezone
from pathlib import Path

BANNER = """
╔══════════════════════════════════════════════════════════╗
║  LAB 7 — Zero Trust & Network Security                  ║
║  Microsegmentation · mTLS · Identity-Aware Access       ║
╚══════════════════════════════════════════════════════════╝
"""

# ─────────────────────────────────────────────
# EXERCISE 1: Network Topology Design
# ─────────────────────────────────────────────
# Model a 3-VLAN Zero Trust lab with Dev, Prod, and Management zones.
# No implicit trust between any zone — all flows must be explicitly allowed.

NETWORK_TOPOLOGY = {
    "vlans": {
        "VLAN_10_DEV": {
            "subnet": "10.10.10.0/24",
            "zone": "development",
            "trust_level": "low",
            "hosts": [
                {"name": "dev-ws-01",  "ip": "10.10.10.10", "role": "developer_workstation"},
                {"name": "dev-ws-02",  "ip": "10.10.10.11", "role": "developer_workstation"},
                {"name": "dev-api-01", "ip": "10.10.10.50", "role": "dev_api_server"},
            ]
        },
        "VLAN_20_PROD": {
            "subnet": "10.20.20.0/24",
            "zone": "production",
            "trust_level": "high",
            "hosts": [
                {"name": "prod-web-01",  "ip": "10.20.20.10", "role": "web_server"},
                {"name": "prod-app-01",  "ip": "10.20.20.20", "role": "app_server"},
                {"name": "prod-db-01",   "ip": "10.20.20.30", "role": "database"},
                {"name": "prod-cache-01","ip": "10.20.20.40", "role": "cache_server"},
            ]
        },
        "VLAN_30_MGMT": {
            "subnet": "10.30.30.0/24",
            "zone": "management",
            "trust_level": "critical",
            "hosts": [
                {"name": "mgmt-bastion", "ip": "10.30.30.5",  "role": "bastion_host"},
                {"name": "mgmt-siem",    "ip": "10.30.30.10", "role": "siem_server"},
                {"name": "mgmt-ca",      "ip": "10.30.30.20", "role": "certificate_authority"},
                {"name": "mgmt-iam",     "ip": "10.30.30.30", "role": "iam_server"},
            ]
        }
    },
    "internet_gateway": "203.0.113.1",
    "identity_aware_proxy": "10.30.30.100"
}


# ─────────────────────────────────────────────
# EXERCISE 2: Zero Trust Policy Engine
# ─────────────────────────────────────────────
# Define explicit allow-list policies. Default = DENY ALL.
# Every flow needs: source identity, destination, port, protocol, mTLS required.

ZERO_TRUST_POLICIES = [
    # Web tier — internet → prod-web
    {
        "id": "P-001", "name": "Internet to Web Server",
        "src_zone": "internet", "dst_zone": "production",
        "dst_host": "prod-web-01", "dst_port": 443,
        "protocol": "HTTPS", "mtls_required": False,
        "identity_required": False, "action": "ALLOW",
        "justification": "Public web traffic — TLS only, no mTLS for unauthenticated users"
    },
    # App tier — web → app (internal, mTLS)
    {
        "id": "P-002", "name": "Web Server to App Server",
        "src_zone": "production", "src_host": "prod-web-01",
        "dst_zone": "production", "dst_host": "prod-app-01",
        "dst_port": 8080, "protocol": "HTTP",
        "mtls_required": True, "identity_required": True,
        "required_identity": "svc-web", "action": "ALLOW",
        "justification": "East-west mTLS: web service cert required, no implicit VLAN trust"
    },
    # DB tier — app → db (mTLS + specific service identity)
    {
        "id": "P-003", "name": "App Server to Database",
        "src_zone": "production", "src_host": "prod-app-01",
        "dst_zone": "production", "dst_host": "prod-db-01",
        "dst_port": 5432, "protocol": "PostgreSQL",
        "mtls_required": True, "identity_required": True,
        "required_identity": "svc-app", "action": "ALLOW",
        "justification": "Only prod-app with svc-app cert may reach DB. No dev or mgmt direct DB access."
    },
    # Mgmt — bastion → any prod (SSH only, with MFA identity)
    {
        "id": "P-004", "name": "Bastion to Production SSH",
        "src_zone": "management", "src_host": "mgmt-bastion",
        "dst_zone": "production", "dst_port": 22,
        "protocol": "SSH", "mtls_required": True,
        "identity_required": True, "required_identity": "ops-engineer",
        "action": "ALLOW",
        "justification": "Admins may SSH to prod only through bastion with MFA-validated identity"
    },
    # SIEM — siem → all zones (log collection, read-only)
    {
        "id": "P-005", "name": "SIEM Log Collection",
        "src_zone": "management", "src_host": "mgmt-siem",
        "dst_zone": "any", "dst_port": 514,
        "protocol": "Syslog/TLS", "mtls_required": True,
        "identity_required": True, "required_identity": "svc-siem",
        "action": "ALLOW",
        "justification": "SIEM pulls logs from all zones using dedicated svc-siem certificate"
    },
    # Dev → Dev API (dev zone self-contained)
    {
        "id": "P-006", "name": "Dev Workstation to Dev API",
        "src_zone": "development", "dst_zone": "development",
        "dst_host": "dev-api-01", "dst_port": 8080,
        "protocol": "HTTP", "mtls_required": False,
        "identity_required": True, "required_identity": "developer",
        "action": "ALLOW",
        "justification": "Dev zone self-contained. Identity token required, mTLS optional in dev."
    },
]


class ZeroTrustPolicyEngine:
    """Evaluates access requests against Zero Trust policies. Default: DENY."""

    def __init__(self, policies: list):
        self.policies = policies
        self.decision_log = []

    def evaluate(self, request: dict) -> dict:
        """
        Evaluate an access request.
        request = {src_zone, src_host, dst_host, dst_port, identity, has_mtls_cert}
        """
        src_zone  = request.get("src_zone", "")
        src_host  = request.get("src_host", "")
        dst_host  = request.get("dst_host", "")
        dst_port  = request.get("dst_port", 0)
        identity  = request.get("identity", None)
        has_cert  = request.get("has_mtls_cert", False)

        for policy in self.policies:
            # Match source zone
            if policy.get("src_zone") not in ("any", src_zone):
                continue
            if policy.get("src_host") and policy["src_host"] != src_host:
                continue
            # Match destination
            if policy.get("dst_zone") not in ("any", None):
                dst_vlan = self._get_zone(dst_host)
                if policy["dst_zone"] != dst_vlan and policy.get("dst_zone") != "any":
                    continue
            if policy.get("dst_host") and policy["dst_host"] != dst_host:
                continue
            if policy.get("dst_port") and policy["dst_port"] != dst_port:
                continue

            # Enforce mTLS requirement
            if policy.get("mtls_required") and not has_cert:
                decision = {
                    "policy": policy["id"],
                    "action": "DENY",
                    "reason": f"Policy {policy['id']} requires mTLS certificate — none presented",
                    "request": request
                }
                self.decision_log.append(decision)
                return decision

            # Enforce identity requirement
            if policy.get("identity_required"):
                required = policy.get("required_identity")
                if not identity:
                    decision = {
                        "policy": policy["id"],
                        "action": "DENY",
                        "reason": f"Policy {policy['id']} requires identity '{required}' — no identity presented",
                        "request": request
                    }
                    self.decision_log.append(decision)
                    return decision
                if required and identity != required:
                    decision = {
                        "policy": policy["id"],
                        "action": "DENY",
                        "reason": f"Identity mismatch: policy requires '{required}', got '{identity}'",
                        "request": request
                    }
                    self.decision_log.append(decision)
                    return decision

            # All checks passed
            decision = {
                "policy": policy["id"],
                "action": "ALLOW",
                "reason": policy["justification"],
                "request": request
            }
            self.decision_log.append(decision)
            return decision

        # No matching policy — default DENY
        decision = {
            "policy": "DEFAULT",
            "action": "DENY",
            "reason": "No matching policy found — Zero Trust default DENY",
            "request": request
        }
        self.decision_log.append(decision)
        return decision

    def _get_zone(self, host: str) -> str:
        for vlan, info in NETWORK_TOPOLOGY["vlans"].items():
            for h in info["hosts"]:
                if h["name"] == host or h["ip"] == host:
                    return info["zone"]
        return "unknown"


# ─────────────────────────────────────────────
# EXERCISE 3: mTLS Certificate Design
# ─────────────────────────────────────────────

CERTIFICATE_INVENTORY = {
    "ca": {
        "name": "ZeroTrustLab-RootCA",
        "type": "Root CA",
        "host": "mgmt-ca (10.30.30.20)",
        "key_algo": "ECDSA P-384",
        "validity_days": 3650,
        "usage": "Signs all intermediate and leaf certs"
    },
    "service_certs": [
        {"cn": "svc-web",     "issued_to": "prod-web-01",  "ttl_hours": 24,   "san": "prod-web-01.ztlab.internal"},
        {"cn": "svc-app",     "issued_to": "prod-app-01",  "ttl_hours": 24,   "san": "prod-app-01.ztlab.internal"},
        {"cn": "svc-siem",    "issued_to": "mgmt-siem",    "ttl_hours": 24,   "san": "siem.ztlab.internal"},
        {"cn": "svc-db",      "issued_to": "prod-db-01",   "ttl_hours": 24,   "san": "db.ztlab.internal"},
    ],
    "identity_certs": [
        {"cn": "ops-engineer", "issued_to": "alice@company.com", "ttl_hours": 8, "mfa_required": True},
        {"cn": "developer",    "issued_to": "bob@company.com",   "ttl_hours": 8, "mfa_required": True},
        {"cn": "svc-app",      "issued_to": "app-service-account","ttl_hours": 24,"mfa_required": False},
    ]
}


def analyze_certificate_design(inventory: dict) -> list:
    findings = []
    ca = inventory["ca"]
    if "P-384" not in ca["key_algo"] and "P-256" not in ca["key_algo"] and "RSA-4096" not in ca["key_algo"]:
        findings.append({"level": "HIGH", "msg": f"CA uses weak key algorithm: {ca['key_algo']}"})
    else:
        findings.append({"level": "PASS", "msg": f"CA key algorithm is strong: {ca['key_algo']}"})

    for cert in inventory.get("service_certs", []):
        if cert["ttl_hours"] > 48:
            findings.append({"level": "MEDIUM", "msg": f"Service cert '{cert['cn']}' TTL is {cert['ttl_hours']}h — recommend ≤24h"})
        else:
            findings.append({"level": "PASS", "msg": f"Service cert '{cert['cn']}' TTL: {cert['ttl_hours']}h ✓"})

    for cert in inventory.get("identity_certs", []):
        if cert["ttl_hours"] > 12 and cert.get("mfa_required"):
            findings.append({"level": "MEDIUM", "msg": f"Identity cert '{cert['cn']}' valid {cert['ttl_hours']}h — consider ≤8h for human identities"})
        if not cert.get("mfa_required") and cert["issued_to"].endswith("@company.com"):
            findings.append({"level": "HIGH", "msg": f"Human identity cert '{cert['cn']}' does NOT require MFA"})

    return findings


# ─────────────────────────────────────────────
# EXERCISE 4: Lateral Movement Simulation
# ─────────────────────────────────────────────
# Simulate an attacker who has compromised dev-ws-01 and
# attempts lateral movement to prod and mgmt zones.

LATERAL_MOVEMENT_SCENARIOS = [
    {
        "name": "Attacker pivots from Dev to Prod DB (direct)",
        "description": "Attacker on dev-ws-01 tries to reach prod-db-01 directly on port 5432",
        "request": {
            "src_zone": "development",
            "src_host": "dev-ws-01",
            "dst_host": "prod-db-01",
            "dst_port": 5432,
            "identity": None,
            "has_mtls_cert": False
        },
        "expected": "DENY"
    },
    {
        "name": "Attacker pivots from Dev to Prod Web on port 80",
        "description": "Attacker tries internal HTTP to prod-web-01 — not a defined policy",
        "request": {
            "src_zone": "development",
            "src_host": "dev-ws-01",
            "dst_host": "prod-web-01",
            "dst_port": 80,
            "identity": "developer",
            "has_mtls_cert": False
        },
        "expected": "DENY"
    },
    {
        "name": "Attacker pivots to Management SIEM",
        "description": "Attacker on dev zone tries to reach SIEM server",
        "request": {
            "src_zone": "development",
            "src_host": "dev-ws-01",
            "dst_host": "mgmt-siem",
            "dst_port": 514,
            "identity": "developer",
            "has_mtls_cert": True
        },
        "expected": "DENY"
    },
    {
        "name": "Attacker stolen svc-web cert tries to hit DB",
        "description": "Attacker stole web server cert and tries to use it against the database",
        "request": {
            "src_zone": "production",
            "src_host": "prod-web-01",
            "dst_host": "prod-db-01",
            "dst_port": 5432,
            "identity": "svc-web",   # Wrong identity — DB requires svc-app
            "has_mtls_cert": True
        },
        "expected": "DENY"
    },
    {
        "name": "Legitimate app → db flow",
        "description": "prod-app-01 with valid svc-app cert connects to database",
        "request": {
            "src_zone": "production",
            "src_host": "prod-app-01",
            "dst_host": "prod-db-01",
            "dst_port": 5432,
            "identity": "svc-app",
            "has_mtls_cert": True
        },
        "expected": "ALLOW"
    },
    {
        "name": "Legitimate bastion → prod SSH",
        "description": "Ops engineer through bastion with MFA cert",
        "request": {
            "src_zone": "management",
            "src_host": "mgmt-bastion",
            "dst_host": "prod-web-01",
            "dst_port": 22,
            "identity": "ops-engineer",
            "has_mtls_cert": True
        },
        "expected": "ALLOW"
    },
]


# ─────────────────────────────────────────────
# EXERCISE 5: Security Posture Score
# ─────────────────────────────────────────────

ZT_PRINCIPLES = [
    {
        "principle": "Verify Explicitly",
        "description": "Every request authenticated via identity + certificate",
        "checks": [
            ("All east-west flows require mTLS", True),
            ("All human access requires MFA", True),
            ("Service accounts use short-lived certs (≤24h)", True),
            ("No anonymous service-to-service calls", True),
        ]
    },
    {
        "principle": "Least Privilege",
        "description": "Minimum required access, no implicit trust between zones",
        "checks": [
            ("Default-deny between all VLANs", True),
            ("DB accessible only from app tier", True),
            ("Dev zone cannot reach prod zone", True),
            ("Management SSH only through bastion", True),
            ("Each service has unique identity cert", True),
        ]
    },
    {
        "principle": "Assume Breach",
        "description": "Lateral movement blocked even with valid credentials",
        "checks": [
            ("Stolen svc-web cert cannot reach DB", True),
            ("SIEM collects logs from all zones", True),
            ("Certificate revocation (OCSP) configured", False),  # Not yet implemented
            ("Micro-segmentation enforced at host level", True),
            ("All access requests logged for audit", True),
        ]
    },
]


def calculate_zt_score(principles: list) -> dict:
    total_checks = sum(len(p["checks"]) for p in principles)
    passed = sum(1 for p in principles for _, result in p["checks"] if result)
    score = round(passed / total_checks * 100, 1)
    maturity = "Optimized" if score >= 90 else "Managed" if score >= 75 else "Defined" if score >= 60 else "Initial"
    return {"score": score, "passed": passed, "total": total_checks, "maturity": maturity}


# ─────────────────────────────────────────────
# Main Lab Runner
# ─────────────────────────────────────────────

def run_lab():
    print(BANNER)
    out = Path("lab7_output")
    out.mkdir(exist_ok=True)

    # Exercise 1 — Topology
    print("[EXERCISE 1] Network Topology — Zero Trust Lab Architecture")
    print("─" * 60)
    for vlan_id, info in NETWORK_TOPOLOGY["vlans"].items():
        trust_color = {"low": "DEV", "high": "PROD", "critical": "MGMT"}[info["trust_level"]]
        print(f"\n  [{trust_color}] {vlan_id}  subnet={info['subnet']}  trust={info['trust_level'].upper()}")
        for host in info["hosts"]:
            print(f"    • {host['name']:<20} {host['ip']:<16} [{host['role']}]")
    print(f"\n  Zero Trust Principle: NO implicit trust between any zone.")
    print(f"  All inter-zone traffic is DENIED by default.\n")

    # Exercise 2 — Policy Engine
    print("[EXERCISE 2] Zero Trust Policy Engine — Policy Definitions")
    print("─" * 60)
    engine = ZeroTrustPolicyEngine(ZERO_TRUST_POLICIES)
    print(f"  Loaded {len(ZERO_TRUST_POLICIES)} explicit allow policies")
    print(f"  Default action for unmatched traffic: DENY\n")
    for p in ZERO_TRUST_POLICIES:
        mtls = "mTLS:✓" if p.get("mtls_required") else "mTLS:✗"
        id_req = f"Identity:{p.get('required_identity','any')}" if p.get("identity_required") else "Identity:none"
        print(f"  [{p['id']}] {p['name']}")
        print(f"         Port:{p['dst_port']} | {mtls} | {id_req} → {p['action']}")

    # Exercise 3 — mTLS Design
    print(f"\n[EXERCISE 3] mTLS Certificate Design Analysis")
    print("─" * 60)
    cert_findings = analyze_certificate_design(CERTIFICATE_INVENTORY)
    for f in cert_findings:
        symbol = "✓" if f["level"] == "PASS" else "⚠" if f["level"] == "MEDIUM" else "✗"
        print(f"  {symbol} [{f['level']:<6}] {f['msg']}")

    # Exercise 4 — Lateral Movement
    print(f"\n[EXERCISE 4] Lateral Movement Simulation")
    print("─" * 60)
    print(f"  Attacker has compromised dev-ws-01. Testing {len(LATERAL_MOVEMENT_SCENARIOS)} pivots...\n")
    all_correct = True
    for scenario in LATERAL_MOVEMENT_SCENARIOS:
        result = engine.evaluate(scenario["request"])
        expected = scenario["expected"]
        correct = result["action"] == expected
        if not correct:
            all_correct = False
        icon = "✓" if correct else "✗ POLICY GAP"
        action_color = "ALLOW" if result["action"] == "ALLOW" else "DENY "
        print(f"  {icon} {scenario['name']}")
        print(f"    → {action_color} | {result['reason']}")
        if not correct:
            print(f"    !! Expected {expected} but got {result['action']} — REVIEW POLICY")
        print()

    if all_correct:
        print("  ✓ All lateral movement attempts DENIED correctly.")
        print("  ✓ Legitimate flows ALLOWED correctly.")

    # Exercise 5 — ZT Score
    print(f"\n[EXERCISE 5] Zero Trust Maturity Score")
    print("─" * 60)
    zt = calculate_zt_score(ZT_PRINCIPLES)
    bar_filled = int(zt["score"] / 100 * 40)
    bar = "█" * bar_filled + "░" * (40 - bar_filled)
    print(f"\n  Overall Score: {zt['score']}% ({zt['passed']}/{zt['total']} checks passed)")
    print(f"  Maturity Level: {zt['maturity']}")
    print(f"  [{bar}]\n")

    for principle in ZT_PRINCIPLES:
        passed = sum(1 for _, r in principle["checks"] if r)
        total = len(principle["checks"])
        print(f"  {principle['principle']} — {passed}/{total}")
        for check_name, result in principle["checks"]:
            symbol = "✓" if result else "✗"
            print(f"    {symbol} {check_name}")

    # Save output
    output_data = {
        "topology": NETWORK_TOPOLOGY,
        "policies": ZERO_TRUST_POLICIES,
        "cert_findings": cert_findings,
        "lateral_movement_results": [
            {
                "scenario": s["name"],
                "expected": s["expected"],
                "result": engine.evaluate(s["request"])
            } for s in LATERAL_MOVEMENT_SCENARIOS
        ],
        "zt_score": zt
    }
    with open(out / "zt_lab_results.json", "w") as f:
        json.dump(output_data, f, indent=2)
    print(f"\n  ✓ Full results saved: lab7_output/zt_lab_results.json")

    print(f"""
╔══════════════════════════════════════════════════════════╗
║  LAB 7 COMPLETE                                         ║
╠══════════════════════════════════════════════════════════╣
║  CHALLENGE 1: Add OCSP stapling to the cert design and  ║
║  push the ZT score from 86% to 100%.                   ║
║                                                          ║
║  CHALLENGE 2: Add a new lateral movement scenario where  ║
║  the attacker replays a captured JWT token instead of   ║
║  using an mTLS cert. Show how token expiry (TTL ≤15min) ║
║  mitigates this.                                        ║
╠══════════════════════════════════════════════════════════╣
║  Key Concepts Covered:                                  ║
║  • Zero Trust Architecture (NIST SP 800-207)            ║
║  • Microsegmentation: default-deny VLAN policies        ║
║  • mTLS certificate design and short-lived certs        ║
║  • Identity-aware proxy access evaluation               ║
║  • East-west lateral movement prevention                ║
║  • Zero Trust maturity scoring (CISA ZTA model)         ║
╚══════════════════════════════════════════════════════════╝""")


if __name__ == "__main__":
    run_lab()
