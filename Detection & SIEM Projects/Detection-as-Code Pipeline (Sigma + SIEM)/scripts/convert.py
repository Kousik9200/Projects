#!/usr/bin/env python3
"""
convert.py - Sigma rule converter for Detection-as-Code pipeline
Converts Sigma YAML rules to Splunk SPL and Microsoft Sentinel KQL

Author: Kousik Gunasekaran
"""

import os
import sys
import json
import yaml
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)


RULES_DIR = Path("rules")
SPLUNK_OUTPUT_DIR = Path("queries/splunk")
SENTINEL_OUTPUT_DIR = Path("queries/sentinel")
REPORT_FILE = Path("queries/conversion_report.json")


# ─────────────────────────────────────────────
# Splunk SPL converter
# ─────────────────────────────────────────────

def build_splunk_condition(detection: dict) -> str:
    """Convert a Sigma detection block to Splunk SPL syntax."""
    clauses = []

    for key, value in detection.items():
        if key == "condition":
            continue

        if isinstance(value, dict):
            field_clauses = []
            for field, matcher in value.items():
                if field == "CommandLine|contains":
                    if isinstance(matcher, list):
                        inner = " OR ".join(f'CommandLine="*{v}*"' for v in matcher)
                        field_clauses.append(f"({inner})")
                    else:
                        field_clauses.append(f'CommandLine="*{matcher}*"')

                elif field == "CommandLine|contains|all":
                    if isinstance(matcher, list):
                        inner = " AND ".join(f'CommandLine="*{v}*"' for v in matcher)
                        field_clauses.append(f"({inner})")

                elif field == "Image|endswith":
                    if isinstance(matcher, list):
                        inner = " OR ".join(f'Image="*{v}"' for v in matcher)
                        field_clauses.append(f"({inner})")
                    else:
                        field_clauses.append(f'Image="*{matcher}"')

                elif field == "EventID":
                    if isinstance(matcher, list):
                        inner = " OR ".join(f"EventID={v}" for v in matcher)
                        field_clauses.append(f"({inner})")
                    else:
                        field_clauses.append(f"EventID={matcher}")

                elif field == "LogonType":
                    if isinstance(matcher, list):
                        inner = " OR ".join(f"LogonType={v}" for v in matcher)
                        field_clauses.append(f"({inner})")

                elif field == "QueryName|endswith":
                    if isinstance(matcher, list):
                        inner = " OR ".join(f'QueryName="*{v}"' for v in matcher)
                        field_clauses.append(f"({inner})")

                else:
                    # generic fallback: field="value"
                    if isinstance(matcher, list):
                        inner = " OR ".join(f'{field.split("|")[0]}="{v}"' for v in matcher)
                        field_clauses.append(f"({inner})")
                    else:
                        field_clauses.append(f'{field.split("|")[0]}="{matcher}"')

            if field_clauses:
                clauses.append("(" + " AND ".join(field_clauses) + ")")

    # Handle timeframe / aggregate conditions
    condition_str = detection.get("condition", "")
    if "count()" in condition_str:
        count_threshold = condition_str.split(">")[-1].strip() if ">" in condition_str else "10"
        by_field = condition_str.split("by")[-1].split(">")[0].strip() if "by" in condition_str else "user"
        return (
            " OR ".join(clauses)
            + f" | stats count by {by_field} | where count > {count_threshold}"
        )

    return " OR ".join(clauses) if clauses else "*"


def sigma_to_splunk(rule: dict) -> str:
    """Generate a full Splunk SPL query from a parsed Sigma rule."""
    title = rule.get("title", "Unknown Rule")
    description = rule.get("description", "")
    tags = rule.get("tags", [])
    detection = rule.get("detection", {})
    logsource = rule.get("logsource", {})

    # Map logsource to Splunk index/sourcetype hints
    index_hint = ""
    if logsource.get("product") == "windows":
        index_hint = 'index=windows '
    elif logsource.get("category") == "dns":
        index_hint = 'index=dns '

    condition = build_splunk_condition(detection)

    spl = f"""| Comment: {title}
| Comment: {description}
| Comment: MITRE ATT&CK Tags: {', '.join(tags)}
{index_hint}sourcetype=WinEventLog:Security
| search {condition}
| table _time, host, user, CommandLine, Image, EventID
| sort -_time"""

    return spl.strip()


# ─────────────────────────────────────────────
# Sentinel KQL converter
# ─────────────────────────────────────────────

def build_kql_condition(detection: dict) -> str:
    """Convert a Sigma detection block to KQL where clause."""
    clauses = []

    for key, value in detection.items():
        if key in ("condition", "timeframe"):
            continue

        if isinstance(value, dict):
            field_clauses = []
            for field, matcher in value.items():
                if "contains" in field:
                    base_field = field.split("|")[0]
                    if isinstance(matcher, list):
                        if "|all" in field:
                            inner = " and ".join(f'{base_field} contains "{v}"' for v in matcher)
                        else:
                            inner = " or ".join(f'{base_field} contains "{v}"' for v in matcher)
                        field_clauses.append(f"({inner})")
                    else:
                        field_clauses.append(f'{base_field} contains "{matcher}"')

                elif "endswith" in field:
                    base_field = field.split("|")[0]
                    if isinstance(matcher, list):
                        inner = " or ".join(f'{base_field} endswith "{v}"' for v in matcher)
                        field_clauses.append(f"({inner})")
                    else:
                        field_clauses.append(f'{base_field} endswith "{matcher}"')

                elif "length" in field:
                    base_field = field.split("|")[0]
                    threshold = str(matcher).replace(">= ", "").replace("> ", "").strip()
                    field_clauses.append(f"strlen({base_field}) >= {threshold}")

                else:
                    base_field = field.split("|")[0]
                    if isinstance(matcher, list):
                        inner = " or ".join(f'{base_field} == {v}' if isinstance(v, int) else f'{base_field} == "{v}"' for v in matcher)
                        field_clauses.append(f"({inner})")
                    else:
                        val = matcher if isinstance(matcher, int) else f'"{matcher}"'
                        field_clauses.append(f"{base_field} == {val}")

            if field_clauses:
                clauses.append("(" + " and ".join(field_clauses) + ")")

    condition_str = detection.get("condition", "")
    if "count()" in condition_str:
        count_threshold = condition_str.split(">")[-1].strip() if ">" in condition_str else "10"
        by_field = condition_str.split("by")[-1].split(">")[0].strip() if "by" in condition_str else "TargetUserName"
        base = " or ".join(clauses) if clauses else "true"
        return (
            base
            + f"\n| summarize FailedAttempts = count() by {by_field}"
            + f"\n| where FailedAttempts > {count_threshold}"
        )

    return " or ".join(clauses) if clauses else "true"


def sigma_to_sentinel(rule: dict) -> str:
    """Generate a Microsoft Sentinel KQL query from a parsed Sigma rule."""
    title = rule.get("title", "Unknown Rule")
    description = rule.get("description", "")
    tags = rule.get("tags", [])
    detection = rule.get("detection", {})
    logsource = rule.get("logsource", {})

    # Map logsource to Sentinel table
    table = "SecurityEvent"
    if logsource.get("category") == "process_creation":
        table = "DeviceProcessEvents"
    elif logsource.get("category") == "dns":
        table = "DnsEvents"
    elif logsource.get("service") == "security":
        table = "SecurityEvent"

    condition = build_kql_condition(detection)
    timeframe = rule.get("detection", {}).get("timeframe", "1h")

    kql = f"""// {title}
// {description}
// MITRE ATT&CK: {', '.join(tags)}
{table}
| where TimeGenerated >= ago({timeframe})
| where {condition}
| project TimeGenerated, Computer, Account, CommandLine, InitiatingProcessFileName, EventID
| sort by TimeGenerated desc"""

    return kql.strip()


# ─────────────────────────────────────────────
# Main conversion runner
# ─────────────────────────────────────────────

def load_sigma_rule(path: Path) -> Optional[dict]:
    """Load and parse a Sigma YAML rule file."""
    try:
        with open(path, "r") as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Failed to load {path}: {e}")
        return None


def convert_all_rules() -> dict:
    """Convert all Sigma rules in the rules directory."""
    SPLUNK_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    SENTINEL_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    report = {
        "generated_at": datetime.utcnow().isoformat(),
        "total_rules": 0,
        "converted": 0,
        "failed": 0,
        "results": []
    }

    rule_files = list(RULES_DIR.glob("*.yml"))
    report["total_rules"] = len(rule_files)

    for rule_path in rule_files:
        logger.info(f"Converting: {rule_path.name}")
        rule = load_sigma_rule(rule_path)

        if not rule:
            report["failed"] += 1
            report["results"].append({"file": rule_path.name, "status": "FAILED", "reason": "Parse error"})
            continue

        stem = rule_path.stem
        try:
            splunk_query = sigma_to_splunk(rule)
            sentinel_query = sigma_to_sentinel(rule)

            splunk_out = SPLUNK_OUTPUT_DIR / f"{stem}.spl"
            sentinel_out = SENTINEL_OUTPUT_DIR / f"{stem}.kql"

            with open(splunk_out, "w") as f:
                f.write(splunk_query)
            with open(sentinel_out, "w") as f:
                f.write(sentinel_query)

            logger.info(f"  [OK] Splunk -> {splunk_out}")
            logger.info(f"  [OK] Sentinel -> {sentinel_out}")
            report["converted"] += 1
            report["results"].append({
                "file": rule_path.name,
                "title": rule.get("title"),
                "status": "OK",
                "splunk": str(splunk_out),
                "sentinel": str(sentinel_out),
                "tags": rule.get("tags", []),
                "level": rule.get("level", "unknown")
            })
        except Exception as e:
            logger.error(f"  [FAIL] {rule_path.name}: {e}")
            report["failed"] += 1
            report["results"].append({"file": rule_path.name, "status": "FAILED", "reason": str(e)})

    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(REPORT_FILE, "w") as f:
        json.dump(report, f, indent=2)

    logger.info(f"\n{'='*50}")
    logger.info(f"Conversion complete: {report['converted']}/{report['total_rules']} rules converted")
    logger.info(f"Report saved to {REPORT_FILE}")

    return report


if __name__ == "__main__":
    report = convert_all_rules()
    if report["failed"] > 0:
        logger.warning(f"{report['failed']} rules failed to convert.")
        sys.exit(1)
    sys.exit(0)
