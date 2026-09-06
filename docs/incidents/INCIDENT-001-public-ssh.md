# Incident 001: Public SSH exposure

## Executive summary

I simulated a high-risk network change by allowing SSH (TCP/22) from `0.0.0.0/0` on an unattached security group. I investigated the change in CloudTrail, removed the rule, verified the remediation event, and deleted the temporary security group. No workload was exposed.

## Evidence and triage

- Resource: `lab4-public-ssh-incident` (identifier sanitized in public evidence)
- Risk event: `AuthorizeSecurityGroupIngress`
- Configuration: TCP/22 from `0.0.0.0/0`
- Actor: `lab-admin`
- Authentication context: MFA authenticated
- Region: `us-east-1`
- Error: none; the API call succeeded

The event parameters confirmed that the change affected SSH and used a public IPv4 CIDR. The security group was not associated with an instance or network interface, so the potential exposure never became reachable.

## Response

1. Confirmed the risky inbound rule in the VPC console.
2. Removed it immediately.
3. Verified `RevokeSecurityGroupIngress` in CloudTrail.
4. Confirmed the security group had zero inbound rules.
5. Deleted the temporary security group and verified `DeleteSecurityGroup`.

## Lessons

Alert on public administrative ports, enrich the alert with actor and MFA context, confirm whether the group is attached, and require both configuration-state and audit-event verification before closing the incident.
