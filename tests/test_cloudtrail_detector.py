import json
import tempfile
import unittest
from pathlib import Path

from scripts.cloudtrail_detector import detect_findings, load_events


def identity():
    return {"userName": "lab-admin", "sessionContext": {"attributes": {"mfaAuthenticated": "true"}}}


def ingress_event(name="AuthorizeSecurityGroupIngress", cidr="0.0.0.0/0", port=22):
    return {
        "eventTime": "2026-09-06T00:00:00Z",
        "eventName": name,
        "userIdentity": identity(),
        "requestParameters": {
            "groupId": "sg-test",
            "ipPermissions": {
                "items": [{
                    "ipProtocol": "tcp",
                    "fromPort": port,
                    "toPort": port,
                    "ipRanges": {"items": [{"cidrIp": cidr}]},
                }]
            },
        },
    }


class DetectorTests(unittest.TestCase):
    def test_sample_has_two_resolved_findings(self):
        sample = Path(__file__).parents[1] / "evidence" / "sanitized-cloudtrail-events.json"
        findings = detect_findings(load_events(sample))
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(finding.status == "RESOLVED" for finding in findings))

    def test_detects_unresolved_public_ssh(self):
        findings = detect_findings([ingress_event()])
        self.assertEqual(findings[0].rule_id, "SG-PUBLIC-ADMIN")
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertEqual(findings[0].status, "OPEN")

    def test_matching_revoke_resolves_finding(self):
        revoke = ingress_event("RevokeSecurityGroupIngress")
        revoke["eventTime"] = "2026-09-06T00:01:00Z"
        findings = detect_findings([ingress_event(), revoke])
        self.assertEqual(findings[0].status, "RESOLVED")
        self.assertEqual(findings[0].resolution_event, "RevokeSecurityGroupIngress")

    def test_ignores_restricted_ssh(self):
        self.assertEqual(detect_findings([ingress_event(cidr="203.0.113.10/32")]), [])

    def test_detects_administrator_access(self):
        event = {
            "eventTime": "2026-09-06T00:00:00Z",
            "eventName": "AttachUserPolicy",
            "userIdentity": identity(),
            "requestParameters": {
                "userName": "test-user",
                "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
            },
        }
        findings = detect_findings([event])
        self.assertEqual(findings[0].severity, "CRITICAL")
        self.assertEqual(findings[0].status, "OPEN")

    def test_loads_records_wrapper(self):
        payload = {"Records": [ingress_event()]}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            self.assertEqual(len(load_events(path)), 1)


if __name__ == "__main__":
    unittest.main()
