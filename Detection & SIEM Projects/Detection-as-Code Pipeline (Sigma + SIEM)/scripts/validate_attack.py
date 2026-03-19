#!/usr/bin/env python3
"""
validate_attack.py - MITRE ATT&CK tag validator for Sigma rules
Verifies all technique IDs in Sigma rules are valid ATT&CK techniques.

Author: Kousik Gunasekaran
"""

import sys
import json
import yaml
import logging
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

RULES_DIR = Path("rules")
ATTACK_CACHE_FILE = Path(".attack_cache.json")

# Known valid ATT&CK Enterprise technique IDs (subset — used as fallback)
KNOWN_VALID_TECHNIQUES = {
    "t1003", "t1003.001", "t1003.002", "t1003.003",
    "t1021", "t1021.002", "t1021.003",
    "t1027",
    "t1048", "t1048.001", "t1048.002",
    "t1053", "t1053.005",
    "t1059", "t1059.001", "t1059.003",
    "t1071", "t1071.004",
    "t1078",
    "t1110", "t1110.001", "t1110.002",
    "t1190",
    "t1547", "t1547.001",
    "t1566", "t1566.001", "t1566.002",
    "t1569", "t1569.002",
}

KNOWN_VALID_TACTICS = {
    "initial_access", "execution", "persistence", "privilege_escalation",
    "defense_evasion", "credential_access", "discovery", "lateral_movement",
    "collection", "command_and_control", "exfiltration", "impact", "reconnaissance"
}


def fetch_attack_techniques() -> Optional[set]:
    """Fetch valid technique IDs from MITRE ATT&CK STIX data."""
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    logger.info("Fetching MITRE ATT&CK technique data...")

    # Check cache
    if ATTACK_CACHE_FILE.exists():
        try:
            with open(ATTACK_CACHE_FILE) as f:
                cached = json.load(f)
                logger.info(f"Using cached ATT&CK data ({len(cached['techniques'])} techniques)")
                return set(cached["techniques"])
        except Exception:
            pass

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "detection-as-code-validator/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())

        techniques = set()
        for obj in data.get("objects", []):
            if obj.get("type") == "attack-pattern":
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        ext_id = ref.get("external_id", "").lower()
                        if ext_id.startswith("t"):
                            techniques.add(ext_id)

        # Save cache
        with open(ATTACK_CACHE_FILE, "w") as f:
            json.dump({"techniques": list(techniques)}, f)

        logger.info(f"Loaded {len(techniques)} ATT&CK techniques from MITRE")
        return techniques

    except Exception as e:
        logger.warning(f"Could not fetch live ATT&CK data: {e}. Using local fallback.")
        return None


def extract_attack_tags(tags: list) -> tuple:
    """Extract ATT&CK technique IDs and tactic names from Sigma tags."""
    techniques = []
    tactics = []

    for tag in tags:
        tag_lower = tag.lower()
        if tag_lower.startswith("attack.t"):
            tech_id = tag_lower.replace("attack.", "")
            techniques.append(tech_id)
        elif tag_lower.startswith("attack."):
            tactic = tag_lower.replace("attack.", "")
            tactics.append(tactic)

    return techniques, tactics


def validate_rule(rule: dict, valid_techniques: set) -> dict:
    """Validate a single Sigma rule's ATT&CK tags."""
    title = rule.get("title", "Unknown")
    tags = rule.get("tags", [])
    result = {
        "title": title,
        "status": "PASS",
        "errors": [],
        "warnings": []
    }

    if not tags:
        result["warnings"].append("No ATT&CK tags found — rule is unclassified")
        result["status"] = "WARN"
        return result

    techniques, tactics = extract_attack_tags(tags)

    # Check that at least one tactic is present
    if not tactics:
        result["warnings"].append("No ATT&CK tactic tag found (e.g., attack.execution)")
        result["status"] = "WARN"

    # Validate each technique
    for tech in techniques:
        if tech not in valid_techniques:
            result["errors"].append(f"Unknown ATT&CK technique ID: {tech}")
            result["status"] = "FAIL"

    # Validate tactics
    for tactic in tactics:
        if tactic not in KNOWN_VALID_TACTICS:
            result["warnings"].append(f"Unrecognized tactic: {tactic}")
            if result["status"] != "FAIL":
                result["status"] = "WARN"

    # Check rule has required fields
    required_fields = ["title", "description", "detection", "level"]
    for field in required_fields:
        if not rule.get(field):
            result["errors"].append(f"Missing required field: {field}")
            result["status"] = "FAIL"

    # Check detection has a condition
    detection = rule.get("detection", {})
    if "condition" not in detection:
        result["errors"].append("Detection block missing 'condition' field")
        result["status"] = "FAIL"

    return result


def validate_all_rules() -> bool:
    """Validate all rules and print a report. Returns True if all pass."""
    valid_techniques = fetch_attack_techniques() or KNOWN_VALID_TECHNIQUES

    rule_files = list(RULES_DIR.glob("*.yml"))
    if not rule_files:
        logger.error(f"No Sigma rules found in {RULES_DIR}")
        return False

    logger.info(f"\nValidating {len(rule_files)} Sigma rules...\n")

    results = []
    fail_count = 0
    warn_count = 0

    for rule_path in rule_files:
        try:
            with open(rule_path) as f:
                rule = yaml.safe_load(f)
            if not rule:
                results.append({"file": rule_path.name, "status": "FAIL", "errors": ["Empty or invalid YAML"]})
                fail_count += 1
                continue

            result = validate_rule(rule, valid_techniques)
            result["file"] = rule_path.name
            results.append(result)

            status_symbol = {"PASS": "✓", "WARN": "⚠", "FAIL": "✗"}.get(result["status"], "?")
            logger.info(f"  {status_symbol} {rule_path.name} [{result['status']}]")
            for err in result.get("errors", []):
                logger.error(f"      ERROR: {err}")
            for warn in result.get("warnings", []):
                logger.warning(f"      WARN:  {warn}")

            if result["status"] == "FAIL":
                fail_count += 1
            elif result["status"] == "WARN":
                warn_count += 1

        except Exception as e:
            logger.error(f"  ✗ {rule_path.name}: {e}")
            fail_count += 1

    print(f"\n{'='*50}")
    print(f"Validation Summary")
    print(f"{'='*50}")
    print(f"  Total rules : {len(rule_files)}")
    print(f"  Passed      : {len(rule_files) - fail_count - warn_count}")
    print(f"  Warnings    : {warn_count}")
    print(f"  Failed      : {fail_count}")
    print(f"{'='*50}\n")

    if fail_count > 0:
        logger.error(f"{fail_count} rule(s) failed ATT&CK validation. Fix before merging.")
        return False

    logger.info("All rules passed ATT&CK validation.")
    return True


if __name__ == "__main__":
    success = validate_all_rules()
    sys.exit(0 if success else 1)
