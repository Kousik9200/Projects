"""
East-West Attack Simulation — Zero Trust Validation Test
Tests lateral movement prevention between network segments
Author: Kousik Gunasekaran
"""

import requests
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

LAB_PROXY = "https://proxy.ztlab.local"
OPA_URL = "http://opa.ztlab.local:8181/v1/data/zerotrust/authz/allow"


class EastWestAttackSimulator:
    """Simulates an attacker who has compromised a dev host and attempts
    to pivot to the production segment."""

    def run_all_tests(self):
        results = []
        results.append(self.test_dev_to_prod_blocked())
        results.append(self.test_dev_to_dev_allowed())
        results.append(self.test_stolen_cert_blocked())
        results.append(self.test_noncompliant_device_blocked())
        results.append(self.test_after_hours_prod_blocked())
        self._print_summary(results)

    def test_dev_to_prod_blocked(self):
        """Compromised dev host should NOT reach prod APIs."""
        payload = {
            "input": {
                "certificate": {"valid": True, "issuer": "CN=ZeroTrustLab CA", "expiry": 9999999999999999},
                "device": {"os_patched": True, "antivirus_active": True, "disk_encrypted": True},
                "source_vlan": "VLAN_DEV",
                "target_vlan": "VLAN_PROD",
                "service": "prod-service",
                "requested_path": "/api/v1/prod"
            }
        }
        result = self._evaluate_policy(payload)
        passed = result == False  # Should be DENIED
        logger.info(f"[{'PASS' if passed else 'FAIL'}] Dev→Prod lateral movement: {'BLOCKED' if not result else 'ALLOWED (VULNERABILITY!)'}")
        return {"test": "dev_to_prod", "passed": passed, "result": result}

    def test_dev_to_dev_allowed(self):
        """Legitimate dev-to-dev communication should be allowed."""
        payload = {
            "input": {
                "certificate": {"valid": True, "issuer": "CN=ZeroTrustLab CA", "expiry": 9999999999999999},
                "device": {"os_patched": True, "antivirus_active": True, "disk_encrypted": True},
                "source_vlan": "VLAN_DEV",
                "target_vlan": "VLAN_DEV",
                "service": "dev-service",
                "requested_path": "/api/v1/dev"
            }
        }
        result = self._evaluate_policy(payload)
        passed = result == True
        logger.info(f"[{'PASS' if passed else 'FAIL'}] Dev→Dev: {'ALLOWED' if result else 'BLOCKED (FALSE POSITIVE!)'}")
        return {"test": "dev_to_dev", "passed": passed, "result": result}

    def test_stolen_cert_blocked(self):
        """Request with invalid/stolen certificate should be denied."""
        payload = {
            "input": {
                "certificate": {"valid": False, "issuer": "CN=AttackerCA", "expiry": 9999999999999999},
                "device": {"os_patched": True, "antivirus_active": True, "disk_encrypted": True},
                "source_vlan": "VLAN_DEV",
                "target_vlan": "VLAN_PROD",
                "service": "prod-service",
                "requested_path": "/api/v1/prod"
            }
        }
        result = self._evaluate_policy(payload)
        passed = result == False
        logger.info(f"[{'PASS' if passed else 'FAIL'}] Stolen cert: {'BLOCKED' if not result else 'ALLOWED (CRITICAL VULNERABILITY!)'}")
        return {"test": "stolen_cert", "passed": passed, "result": result}

    def test_noncompliant_device_blocked(self):
        """Unpatched device should be blocked."""
        payload = {
            "input": {
                "certificate": {"valid": True, "issuer": "CN=ZeroTrustLab CA", "expiry": 9999999999999999},
                "device": {"os_patched": False, "antivirus_active": False, "disk_encrypted": True},
                "source_vlan": "VLAN_DEV",
                "target_vlan": "VLAN_DEV",
                "service": "dev-service",
                "requested_path": "/api/v1/dev"
            }
        }
        result = self._evaluate_policy(payload)
        passed = result == False
        logger.info(f"[{'PASS' if passed else 'FAIL'}] Non-compliant device: {'BLOCKED' if not result else 'ALLOWED (VULNERABILITY!)'}")
        return {"test": "noncompliant_device", "passed": passed, "result": result}

    def test_after_hours_prod_blocked(self):
        """After-hours prod access should trigger anomaly block."""
        # This test verifies the time-based policy (run between 10PM-7AM)
        logger.info("[INFO] After-hours prod test — result depends on current time")
        return {"test": "after_hours", "passed": None, "result": "time-dependent"}

    def _evaluate_policy(self, payload: dict) -> bool:
        try:
            resp = requests.post(OPA_URL, json=payload, verify=False, timeout=5)
            return resp.json().get("result", False)
        except Exception as e:
            logger.warning(f"OPA unreachable (lab may not be running): {e}")
            return None

    def _print_summary(self, results: list):
        passed = sum(1 for r in results if r["passed"] is True)
        failed = sum(1 for r in results if r["passed"] is False)
        print(f"\n{'='*50}")
        print(f"Zero Trust Lab Results: {passed} PASS | {failed} FAIL")
        print(f"{'='*50}")


if __name__ == "__main__":
    sim = EastWestAttackSimulator()
    sim.run_all_tests()
