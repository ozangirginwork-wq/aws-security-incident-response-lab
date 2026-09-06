#!/usr/bin/env python3
"""Detect and correlate risky AWS changes in CloudTrail management events."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable


PUBLIC_CIDRS = {"0.0.0.0/0", "::/0"}
SENSITIVE_PORTS = {
    22: ("SSH", "HIGH"),
    3389: ("RDP", "HIGH"),
}
PRIVILEGED_POLICIES = {
    "AdministratorAccess": "CRITICAL",
    "IAMFullAccess": "HIGH",
    "PowerUserAccess": "HIGH",
}


@dataclass
class Finding:
    """A risky change and its remediation state."""

    key: str
    rule_id: str
    severity: str
    title: str
    resource: str
    actor: str
    detected_at: str
    evidence: dict[str, Any]
    status: str = "OPEN"
    resolved_at: str | None = None
    resolution_event: str | None = None

    def resolve(self, event: dict[str, Any]) -> None:
        self.status = "RESOLVED"
        self.resolved_at = str(event.get("eventTime", "unknown"))
        self.resolution_event = str(event.get("eventName", "unknown"))

    def as_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result.pop("key")
        return result


def load_events(path: Path) -> list[dict[str, Any]]:
    """Load a JSON array, a single event, or a CloudTrail Records wrapper."""

    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict) and "Records" in payload:
        payload = payload["Records"]
    elif isinstance(payload, dict):
        payload = [payload]

    if not isinstance(payload, list) or not all(isinstance(item, dict) for item in payload):
        raise ValueError("expected a CloudTrail event, event array, or object with Records")
    return payload


def _items(value: Any) -> list[dict[str, Any]]:
    """Normalize CloudTrail's list or {items: [...]} collection shapes."""

    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        nested = value.get("items", [])
        if isinstance(nested, list):
            return [item for item in nested if isinstance(item, dict)]
    return []


def _actor(event: dict[str, Any]) -> str:
    identity = event.get("userIdentity", {})
    if not isinstance(identity, dict):
        return "unknown"
    return str(identity.get("userName") or identity.get("arn") or identity.get("principalId") or "unknown")


def _public_cidrs(permission: dict[str, Any]) -> set[str]:
    cidrs: set[str] = set()
    for entry in _items(permission.get("ipRanges")):
        value = entry.get("cidrIp")
        if value in PUBLIC_CIDRS:
            cidrs.add(str(value))
    for entry in _items(permission.get("ipv6Ranges")):
        value = entry.get("cidrIpv6")
        if value in PUBLIC_CIDRS:
            cidrs.add(str(value))
    return cidrs


def _sensitive_ports(permission: dict[str, Any]) -> set[int]:
    protocol = str(permission.get("ipProtocol", "")).lower()
    if protocol not in {"tcp", "6", "-1"}:
        return set()

    if protocol == "-1":
        return set(SENSITIVE_PORTS)

    try:
        start = int(permission.get("fromPort"))
        end = int(permission.get("toPort"))
    except (TypeError, ValueError):
        return set()
    return {port for port in SENSITIVE_PORTS if start <= port <= end}


def _security_group_keys(event: dict[str, Any]) -> Iterable[tuple[str, int, str]]:
    request = event.get("requestParameters", {})
    if not isinstance(request, dict):
        return
    group_id = str(request.get("groupId", "unknown-security-group"))
    permissions = _items(request.get("ipPermissions"))
    for permission in permissions:
        for port in _sensitive_ports(permission):
            for cidr in _public_cidrs(permission):
                yield group_id, port, cidr


def detect_findings(events: list[dict[str, Any]]) -> list[Finding]:
    """Return risky changes correlated with later remediation events."""

    findings: list[Finding] = []
    open_findings: dict[str, Finding] = {}

    for event in sorted(events, key=lambda item: str(item.get("eventTime", ""))):
        event_name = event.get("eventName")
        request = event.get("requestParameters", {})
        if not isinstance(request, dict):
            request = {}

        if event_name == "AuthorizeSecurityGroupIngress":
            for group_id, port, cidr in _security_group_keys(event):
                service, severity = SENSITIVE_PORTS[port]
                key = f"sg:{group_id}:{port}:{cidr}"
                finding = Finding(
                    key=key,
                    rule_id="SG-PUBLIC-ADMIN",
                    severity=severity,
                    title=f"Public {service} access from {cidr}",
                    resource=group_id,
                    actor=_actor(event),
                    detected_at=str(event.get("eventTime", "unknown")),
                    evidence={"eventName": event_name, "port": port, "cidr": cidr},
                )
                findings.append(finding)
                open_findings[key] = finding

        elif event_name == "RevokeSecurityGroupIngress":
            for group_id, port, cidr in _security_group_keys(event):
                key = f"sg:{group_id}:{port}:{cidr}"
                finding = open_findings.pop(key, None)
                if finding:
                    finding.resolve(event)

        elif event_name == "AttachUserPolicy":
            policy_arn = str(request.get("policyArn", ""))
            policy_name = policy_arn.rsplit("/", 1)[-1]
            severity = PRIVILEGED_POLICIES.get(policy_name)
            if severity:
                user_name = str(request.get("userName", "unknown-user"))
                key = f"iam:{user_name}:{policy_arn}"
                finding = Finding(
                    key=key,
                    rule_id="IAM-PRIVILEGED-POLICY",
                    severity=severity,
                    title=f"Privileged policy {policy_name} attached directly",
                    resource=user_name,
                    actor=_actor(event),
                    detected_at=str(event.get("eventTime", "unknown")),
                    evidence={"eventName": event_name, "policyArn": policy_arn},
                )
                findings.append(finding)
                open_findings[key] = finding

        elif event_name == "DetachUserPolicy":
            policy_arn = str(request.get("policyArn", ""))
            user_name = str(request.get("userName", "unknown-user"))
            key = f"iam:{user_name}:{policy_arn}"
            finding = open_findings.pop(key, None)
            if finding:
                finding.resolve(event)

        elif event_name == "DeleteSecurityGroup":
            group_id = str(request.get("groupId", ""))
            for key, finding in list(open_findings.items()):
                if key.startswith(f"sg:{group_id}:"):
                    finding.resolve(event)
                    open_findings.pop(key)

        elif event_name == "DeleteUser":
            user_name = str(request.get("userName", ""))
            for key, finding in list(open_findings.items()):
                if key.startswith(f"iam:{user_name}:"):
                    finding.resolve(event)
                    open_findings.pop(key)

    return findings


def render_text(findings: list[Finding]) -> str:
    lines = [
        f"[{finding.severity}] {finding.status} {finding.rule_id}: {finding.title}"
        for finding in findings
    ]
    open_count = sum(finding.status == "OPEN" for finding in findings)
    lines.append(
        f"Summary: {len(findings)} risky changes, {open_count} open, "
        f"{len(findings) - open_count} resolved"
    )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("event_file", type=Path, help="CloudTrail JSON file")
    parser.add_argument("--json", action="store_true", help="emit machine-readable findings")
    parser.add_argument(
        "--fail-on-open",
        action="store_true",
        help="exit with status 2 if any risky finding remains open",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        events = load_events(args.event_file)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        parser.error(str(exc))

    findings = detect_findings(events)
    if args.json:
        print(json.dumps([finding.as_dict() for finding in findings], indent=2))
    else:
        print(render_text(findings))

    if args.fail_on_open and any(finding.status == "OPEN" for finding in findings):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
