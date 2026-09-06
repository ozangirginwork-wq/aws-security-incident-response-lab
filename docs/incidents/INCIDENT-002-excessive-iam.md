# Incident 002: Excessive IAM privilege

## Executive summary

I simulated privilege escalation by directly attaching the AWS-managed `AdministratorAccess` policy to a temporary IAM user. I investigated the action in CloudTrail, detached the policy, verified the remediation event, and deleted the user. The account experienced no actual privilege use because the identity had no credentials or activity.

## Evidence and triage

- Target: `incident-test-user`
- Risk event: `AttachUserPolicy`
- Policy: `arn:aws:iam::aws:policy/AdministratorAccess`
- Actor: `lab-admin`
- Authentication context: MFA authenticated
- Error: none; the API call succeeded
- Target access: no console password, access keys, group membership, or prior activity

The API call was authenticated and successful, but its security impact depended on whether the target could sign in or call APIs. The target had no usable credentials, which limited the scenario to a permission-state change.

## Response

1. Confirmed the directly attached policy on the IAM user.
2. Detached `AdministratorAccess`.
3. Confirmed the user had zero permission policies.
4. Verified `DetachUserPolicy` in CloudTrail.
5. Deleted the temporary user and verified `DeleteUser`.

## Lessons

Alert on privileged policy attachment, identify both actor and target, inspect the target's credentials and recent activity, remove excessive access, and verify the compensating event before closing the incident.
