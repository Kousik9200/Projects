"""
compliance_pipeline.py — GRC Automation & Continuous Compliance Pipeline
Main orchestrator: collect evidence → validate controls → package → alert.

Usage:
    python compliance_pipeline.py           # live run (needs AWS creds)
    python compliance_pipeline.py --demo    # demo mode (no creds needed)
"""

import argparse
import json
import logging
import sys
from datetime import datetime, timezone

from compliance_collector import ComplianceCollector
from control_validator    import ControlValidator
from evidence_packager    import EvidencePackager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)


def print_summary(results: list[dict]):
    passing = [r for r in results if r["status"] == "PASS"]
    failing = [r for r in results if r["status"] == "FAIL"]
    score   = round(len(passing) / max(len(results), 1) * 100, 1)

    print("\n" + "═" * 70)
    print("  SOC 2 CONTINUOUS COMPLIANCE PIPELINE — RESULTS")
    print("═" * 70)
    print(f"  Compliance Score: {score}%   ({len(passing)} pass / {len(failing)} fail)")
    print("─" * 70)

    if failing:
        print("  ❌ FAILING CONTROLS:")
        for r in failing:
            print(f"     [{r['control_id']}] {r['description'][:55]}")
            for gap in r["gaps"]:
                print(f"          → {gap}")
    else:
        print("  ✅ All controls passing!")

    print("═" * 70 + "\n")


def main():
    parser = argparse.ArgumentParser(description="GRC Automation & Continuous Compliance Pipeline")
    parser.add_argument("--demo",    action="store_true", help="Run with mock data (no AWS creds needed)")
    parser.add_argument("--profile", default="default",   help="AWS profile")
    parser.add_argument("--output",  default="./evidence", help="Output directory for evidence package")
    args = parser.parse_args()

    # ── Collect evidence ──────────────────────────────────────────────────────
    if args.demo:
        log.info("Running in DEMO mode …")
        aws_session = None
    else:
        try:
            import boto3
            aws_session = boto3.Session(profile_name=args.profile)
        except ImportError:
            log.error("boto3 not installed. Run: pip install boto3  (or use --demo)")
            sys.exit(1)

    collector = ComplianceCollector(aws_session=aws_session)
    evidence  = collector.collect_all()

    # ── Validate controls ──────────────────────────────────────────────────────
    validator = ControlValidator(evidence)
    results   = validator.validate_all()

    # ── Print summary ─────────────────────────────────────────────────────────
    print_summary(results)

    # ── Package evidence ──────────────────────────────────────────────────────
    packager = EvidencePackager(evidence, results)
    zip_path = packager.package(output_dir=args.output)
    log.info("Evidence package ready: %s", zip_path)

    # ── Exit code for CI/CD ───────────────────────────────────────────────────
    failing = [r for r in results if r["status"] == "FAIL"]
    critical_gaps = [r for r in failing if any("100%" in g or "0 " in g for g in r["gaps"])]
    if critical_gaps:
        log.error("%d critical compliance gaps detected — failing pipeline", len(critical_gaps))
        sys.exit(1)


if __name__ == "__main__":
    main()
