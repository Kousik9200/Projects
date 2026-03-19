# Threat Model — Berbera-Ethiopia Logistics CPTS

## System Overview
The Cyber-Physical Tracking System (CPTS) monitors high-value construction materials
across the Berbera (Somaliland) to Addis Ababa (Ethiopia) trade corridor.

## Assets Under Protection
1. RFID-tagged cargo pallets
2. GPS tracking devices on transport vehicles
3. Digital Bill of Lading (dBoL) system
4. Checkpoint access control infrastructure
5. Central logistics monitoring dashboard

## STRIDE Threat Analysis

### Spoofing
- **GPS Signal Spoofing**: Attacker broadcasts false GPS coordinates to misrepresent cargo location
  - Likelihood: HIGH (commodity GPS spoofing equipment widely available in region)
  - Impact: CRITICAL — Cargo theft, regulatory non-compliance
  - Control: GPS signal authentication, multi-constellation receivers, anomaly detection

- **RFID Tag Cloning**: Attacker clones RFID tags to bypass checkpoint verification
  - Likelihood: MEDIUM
  - Impact: HIGH — Unauthorized cargo substitution
  - Control: Cryptographic RFID (ISO 15693 + AES-128), rolling authentication codes

### Tampering
- **Digital Bill of Lading Manipulation**: Unauthorized modification of cargo manifest
  - Likelihood: MEDIUM
  - Impact: CRITICAL — Fraudulent cargo release, customs violations
  - Control: Blockchain-anchored dBoL with immutable audit log, PKI signatures

- **Sensor Data Manipulation**: Tampering with temperature/humidity IoT sensor readings
  - Likelihood: LOW
  - Impact: MEDIUM
  - Control: Signed sensor telemetry, threshold anomaly alerts

### Repudiation
- **Checkpoint Denial**: Operator denies approving cargo release
  - Control: Non-repudiation via PKI-signed transactions, SIEM audit trail

### Information Disclosure
- **Network Interception at Checkpoints**: Eavesdropping on vehicle-to-checkpoint comms
  - Control: mTLS 1.3 for all communications, VPN tunnels between zones

### Denial of Service
- **GPS Jamming**: RF jamming to disable vehicle tracking
  - Control: Dead-reckoning fallback, offline checkpoint verification mode

### Elevation of Privilege
- **Compromise of Checkpoint Operator Account**: Attacker gains admin access to dBoL
  - Control: Zero Trust access, MFA, privileged access workstations, session recording

## Data Flow Diagram

```
[Vehicle RFID/GPS] → [Checkpoint Reader] → [Edge Gateway] → [Central SIEM]
                            ↓
                    [dBoL Validation]
                            ↓
                    [Blockchain Ledger]
```

## Risk Register

| ID  | Threat                  | Likelihood | Impact   | Risk  | Owner        |
|-----|-------------------------|------------|----------|-------|--------------|
| T01 | GPS Spoofing            | HIGH       | CRITICAL | CRIT  | Security Ops |
| T02 | RFID Cloning            | MEDIUM     | HIGH     | HIGH  | Security Ops |
| T03 | dBoL Tampering          | MEDIUM     | CRITICAL | HIGH  | Dev Team     |
| T04 | Network Interception    | LOW        | HIGH     | MED   | NetOps       |
| T05 | Insider Threat          | MEDIUM     | HIGH     | HIGH  | HR + SecOps  |
| T06 | GPS Jamming             | LOW        | HIGH     | MED   | SecOps       |
| T07 | Checkpoint DoS          | LOW        | MEDIUM   | LOW   | NetOps       |
