"""
WebSecScan Auditor - OWASP Top 10 Web Security Scanner
"""

import aiohttp
import logging
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)

OWASP_CHECKS = [
    "sql_injection",
    "xss",
    "broken_auth",
    "sensitive_data_exposure",
    "security_misconfiguration",
    "missing_security_headers",
    "directory_traversal",
    "open_redirect",
]


class WebSecAgent:
    def __init__(self):
        self.findings = []

    async def audit(self, target_url: str) -> dict:
        logger.info(f"Starting WebSecScan on: {target_url}")
        self.findings = []

        async with aiohttp.ClientSession() as session:
            await self._check_security_headers(session, target_url)
            await self._check_sql_injection(session, target_url)
            await self._check_xss(session, target_url)
            await self._check_open_redirect(session, target_url)
            await self._check_directory_listing(session, target_url)

        return {
            "target": target_url,
            "total_findings": len(self.findings),
            "critical": [f for f in self.findings if f["severity"] == "CRITICAL"],
            "high": [f for f in self.findings if f["severity"] == "HIGH"],
            "medium": [f for f in self.findings if f["severity"] == "MEDIUM"],
            "all_findings": self.findings
        }

    async def _check_security_headers(self, session, url):
        required_headers = {
            "Strict-Transport-Security": "HIGH",
            "Content-Security-Policy": "HIGH",
            "X-Frame-Options": "MEDIUM",
            "X-Content-Type-Options": "MEDIUM",
            "Referrer-Policy": "LOW",
        }
        try:
            async with session.get(url) as resp:
                for header, severity in required_headers.items():
                    if header.lower() not in [h.lower() for h in resp.headers]:
                        self.findings.append({
                            "check": "Missing Security Header",
                            "detail": f"{header} not present",
                            "severity": severity,
                            "owasp": "A05:2021 Security Misconfiguration"
                        })
        except Exception as e:
            logger.error(f"Header check failed: {e}")

    async def _check_sql_injection(self, session, url):
        payloads = ["'", "' OR '1'='1", "'; DROP TABLE users;--"]
        for payload in payloads:
            test_url = f"{url}?id={payload}"
            try:
                async with session.get(test_url) as resp:
                    body = await resp.text()
                    if any(err in body.lower() for err in ["sql", "syntax", "mysql", "ora-", "pg::"]):
                        self.findings.append({
                            "check": "SQL Injection",
                            "detail": f"Possible SQLi with payload: {payload}",
                            "severity": "CRITICAL",
                            "owasp": "A03:2021 Injection"
                        })
                        break
            except Exception:
                pass

    async def _check_xss(self, session, url):
        payload = "<script>alert('xss')</script>"
        test_url = f"{url}?q={payload}"
        try:
            async with session.get(test_url) as resp:
                body = await resp.text()
                if payload in body:
                    self.findings.append({
                        "check": "Reflected XSS",
                        "detail": "Script payload reflected in response",
                        "severity": "HIGH",
                        "owasp": "A03:2021 Injection"
                    })
        except Exception:
            pass

    async def _check_open_redirect(self, session, url):
        test_url = f"{url}?redirect=https://evil.com"
        try:
            async with session.get(test_url, allow_redirects=False) as resp:
                location = resp.headers.get("Location", "")
                if "evil.com" in location:
                    self.findings.append({
                        "check": "Open Redirect",
                        "detail": f"Redirects to external URL: {location}",
                        "severity": "MEDIUM",
                        "owasp": "A01:2021 Broken Access Control"
                    })
        except Exception:
            pass

    async def _check_directory_listing(self, session, url):
        test_paths = ["/backup/", "/admin/", "/.git/", "/config/"]
        for path in test_paths:
            test_url = urljoin(url, path)
            try:
                async with session.get(test_url) as resp:
                    if resp.status == 200:
                        body = await resp.text()
                        if "index of" in body.lower():
                            self.findings.append({
                                "check": "Directory Listing Enabled",
                                "detail": f"Directory listing at: {path}",
                                "severity": "MEDIUM",
                                "owasp": "A05:2021 Security Misconfiguration"
                            })
            except Exception:
                pass
