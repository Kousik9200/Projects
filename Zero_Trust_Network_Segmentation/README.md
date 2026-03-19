# Zero Trust Network Segmentation Lab

A virtualized Zero Trust network architecture lab enforcing microsegmentation, mutual TLS, identity-aware proxies, and least-privilege access. Validated against insider threat and east-west attack scenarios.

## Lab Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    ZERO TRUST LAB                            │
│                                                              │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐              │
│  │ VLAN 10  │    │ VLAN 20  │    │ VLAN 30  │              │
│  │  Dev     │    │  Prod    │    │  Mgmt    │              │
│  └────┬─────┘    └────┬─────┘    └────┬─────┘              │
│       │               │               │                      │
│       └───────────────┴───────┬───────┘                     │
│                               │                              │
│                    ┌──────────▼──────────┐                  │
│                    │  Identity-Aware      │                  │
│                    │  Proxy (OpenZiti)    │                  │
│                    └──────────┬──────────┘                  │
│                               │                              │
│                    ┌──────────▼──────────┐                  │
│                    │  Policy Engine       │                  │
│                    │  (Cisco ISE / OPA)   │                  │
│                    └─────────────────────┘                  │
└──────────────────────────────────────────────────────────────┘
```

## Components

| Component | Tool | Purpose |
|-----------|------|---------|
| Network Segmentation | Palo Alto VM-Series | VLAN microsegmentation |
| Identity-Aware Proxy | OpenZiti | mTLS + zero trust access |
| Policy Engine | Cisco ISE / OPA | Dynamic access decisions |
| PKI | Step-CA | Certificate management |
| Monitoring | Wazuh | Endpoint + network telemetry |

## Zero Trust Principles Applied

1. **Verify Explicitly** — Every request authenticated via mTLS + identity token
2. **Least Privilege** — Per-service access policies, no implicit trust between VLANs
3. **Assume Breach** — East-west traffic inspected, lateral movement blocked by default

## Setup Instructions

### 1. Deploy Virtual Network
```bash
# Requires: VMware Workstation / VirtualBox
./scripts/deploy_lab.sh
```

### 2. Configure PKI
```bash
cd pki/
step ca init --name "ZeroTrustLab" --dns "ca.ztlab.local" --address ":9000"
```

### 3. Deploy OpenZiti
```bash
docker-compose up -d ziti-controller ziti-router
./scripts/enroll_services.sh
```

### 4. Apply Firewall Policies
```bash
# Palo Alto policies applied via Panorama API
python3 scripts/apply_palo_policies.py --env lab
```

## Test Scenarios

- `tests/east_west_attack.py` — Simulates lateral movement between VLANs
- `tests/insider_threat.py` — Simulates insider accessing unauthorized segment
- `tests/credential_theft.py` — Simulates stolen credential usage
