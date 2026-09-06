# Sanitized CloudTrail evidence

This directory contains a privacy-safe reconstruction of the CloudTrail management events observed during the lab. It is suitable for testing and public portfolio review.

Preserved:

- event names, services, regions, and chronological order;
- IAM actor and MFA state;
- affected resource types and logical names;
- security-group protocol, ports, and CIDRs;
- attached IAM policy and subsequent remediation actions.

Replaced:

- AWS account ID with `111122223333`;
- source IP with documentation address `198.51.100.24`;
- access-key, request, event, VPC, and security-group identifiers with synthetic values.

The raw console screenshots are excluded because they expose identifying account and session metadata. This dataset contains no passwords, MFA seeds, secret access keys, or session tokens.
