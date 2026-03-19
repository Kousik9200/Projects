# CPTS Security Architecture — Berbera Logistics

Cybersecurity architecture design for a Cyber-Physical Tracking System (CPTS) securing high-value construction materials from Somaliland's Berbera port through the Ethiopia logistics corridor.

## Project Scope

| Layer | Description |
|-------|-------------|
| Physical | RFID readers, GPS trackers, IoT sensors on cargo |
| Network | Secure VPN tunnels between checkpoints |
| Application | Digital Bill of Lading (dBoL) system |
| Cloud | Centralized monitoring dashboard |

## Threat Model (MITRE ATT&CK for ICS)

### High-Risk Attack Vectors

| Threat | Technique | Mitigation |
|--------|-----------|------------|
| GPS Spoofing | T0856 Spoof Reporting Message | Signal authentication + anomaly detection |
| RFID Cloning | T0830 Adversary-in-the-Middle | Cryptographic RFID with rolling codes |
| Supply Chain Tampering | T0831 Manipulation of Control | Tamper-evident seals + blockchain logging |
| Unauthorized dBoL Access | T0866 Exploitation of Remote Services | MFA + Zero Trust access control |
| Network Interception | T0885 Commonly Used Port | mTLS + end-to-end encryption |

## Zero Trust Architecture

```
Berbera Port ──[mTLS]──► Checkpoint 1 ──[mTLS]──► Checkpoint 2 ──[mTLS]──► Addis Ababa
      │                       │                        │                          │
      └───────────────────────┴────────────────────────┴──────────────────────────┘
                                           │
                              ┌────────────▼────────────┐
                              │   Central Monitoring    │
                              │   Dashboard (SIEM)      │
                              └─────────────────────────┘
```

## Security Controls

### NIST SP 800-82 Compliance
- **ICS-CERT** guidelines for OT/ICS environments
- Network segmentation between IT and OT zones
- Air-gapped critical control systems where feasible
- Regular firmware integrity verification

### PKI Infrastructure
- Certificate Authority per logistics zone
- Short-lived certificates (24-hour TTL) for device auth
- OCSP stapling for real-time revocation checks

### Monitoring & Detection
- Anomaly detection on GPS coordinate deviation (>50m threshold)
- RFID scan frequency monitoring
- Network flow analysis at all ingress/egress points

## Architecture Diagrams
See `/diagrams/` folder for full network topology and data flow diagrams.

## References
- NIST SP 800-82 Rev 3 (ICS Security Guide)
- MITRE ATT&CK for ICS v14
- CISA ICS-CERT Advisories
- ISO/IEC 62443 (Industrial Cybersecurity)
