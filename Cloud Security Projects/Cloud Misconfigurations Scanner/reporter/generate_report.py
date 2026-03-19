#!/usr/bin/env python3
"""
generate_report.py - Renders the HTML report from Jinja2 template and scan findings.

Author: Kousik Gunasekaran
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

try:
    from jinja2 import Environment, FileSystemLoader
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False
    logger.warning("jinja2 not installed. HTML report will not be generated.")


TEMPLATE_DIR = Path(__file__).parent
TEMPLATE_FILE = "report.html.j2"
OUTPUT_DIR = Path("output")


def render_html_report(
    findings: list,
    summary: dict,
    account_id: str = "123456789012",
    region: str = "us-east-1",
    environment: str = "prod",
    output_path: Optional[Path] = None
) -> Optional[Path]:
    """Render the HTML report using the Jinja2 template."""
    if not JINJA2_AVAILABLE:
        logger.error("Install jinja2: pip install jinja2")
        return None

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    if output_path is None:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        output_path = OUTPUT_DIR / f"scan_report_{ts}.html"

    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)))
    template = env.get_template(TEMPLATE_FILE)

    html = template.render(
        findings=findings,
        summary=summary,
        account_id=account_id,
        region=region,
        environment=environment,
        scanned_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    )

    with open(output_path, "w") as f:
        f.write(html)

    logger.info(f"HTML report written to: {output_path}")
    return output_path


def save_json_report(
    findings: list,
    summary: dict,
    output_path: Optional[Path] = None
) -> Path:
    """Save findings as a machine-readable JSON report."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    if output_path is None:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        output_path = OUTPUT_DIR / f"scan_report_{ts}.json"

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "findings": findings
    }

    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)

    logger.info(f"JSON report written to: {output_path}")
    return output_path
