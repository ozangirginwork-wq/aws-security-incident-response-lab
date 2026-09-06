# Deployment and cleanup runbook

## Purpose

Deploy the secure network baseline for a short validation exercise and remove it immediately afterward. Deployment is optional; formatting, validation, and security scanning can be performed locally without AWS credentials.

## Safety checks

- Confirm you are using a dedicated lab account or tightly controlled sandbox.
- Confirm the AWS identity and account: `aws sts get-caller-identity`.
- Confirm the selected Region and Availability Zone match.
- Review current AWS pricing and the Billing dashboard.
- Do not deploy anything inside `scenarios/`.
- Never commit credentials, `.tfstate` files, or plan files.

## Validate

```bash
terraform fmt -check -recursive
terraform init -backend=false
terraform validate
```

## Plan

```bash
terraform plan -out=tfplan
terraform show tfplan
```

Expected resources are limited to a VPC, two subnets, an internet gateway, two route tables, two route-table associations, two purpose-built security groups, and the locked-down default security group.

Stop if the plan contains compute, public IP addresses, NAT Gateway, load balancers, databases, or resources you do not understand.

## Deploy and verify

```bash
terraform apply tfplan
terraform output
```

Capture evidence without recording account IDs or other sensitive information.

## Clean up

```bash
terraform destroy
```

Read the destroy plan, type `yes` only after confirming the target resources, and then verify in the AWS console that the lab resources no longer exist.

## Troubleshooting record

For each problem, record:

- Symptom
- Evidence collected
- Root cause
- Resolution
- Verification
- Prevention
