# FINDING-001: SSH exposed to the internet

| Field | Value |
|---|---|
| Severity | High |
| Status | Remediated in secure baseline |
| Asset | Training security group |
| Detection method | Infrastructure-as-Code security scan |
| CWE | CWE-284: Improper Access Control |

## Finding

The training fixture allows inbound TCP port 22 from `0.0.0.0/0`. Any internet host could attempt to connect to a resource associated with this security group.

## Risk

Public SSH exposure increases the attack surface and enables password guessing, credential-stuffing, vulnerability exploitation, and reconnaissance. A compromised administrative service could provide an attacker with an initial foothold inside the cloud environment.

## Evidence

File: `scenarios/insecure-security-group/main.tf`

```hcl
from_port   = 22
to_port     = 22
protocol    = "tcp"
cidr_blocks = ["0.0.0.0/0"]
```

## Remediation

The secure baseline creates no SSH rule. Administrative access should use a managed access method such as AWS Systems Manager Session Manager where applicable. If SSH is an explicit business requirement, limit the source to an approved administrative CIDR and add monitoring, key-management, and time-bound access controls.

## Verification

1. Search the secure Terraform root for inbound port `22` rules.
2. Run Checkov against the secure root and confirm there is no public-SSH finding.
3. Scan the scenario separately and confirm the unsafe rule is detected.
4. Review the Terraform plan before any deployment.

## Lessons learned

Security controls are easier to verify when they are represented in version-controlled code. An isolated unsafe fixture makes the detection reproducible without placing the deployable environment at risk.
