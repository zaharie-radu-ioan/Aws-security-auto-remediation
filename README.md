# AWS Automated Security Remediation

An event-driven pipeline on AWS that detects EC2 security groups exposing SSH (port 22) to the public internet, revokes the offending rule automatically, records an audit entry, and sends an email alert, all within seconds of the misconfiguration being introduced.

Built to explore event-driven architecture and the detect–respond–audit pattern in cloud security.

---

## The problem

Opening SSH to `0.0.0.0/0` is one of the most common cloud misconfigurations and a frequent initial access vector. Manual review doesn't scale, and periodic scans leave a window of exposure. This project closes that window by reacting to the API call itself.

## Architecture

```
IAM User → EC2 Security Group (SSH 0.0.0.0/0)
              │
              ▼
         CloudTrail  (logs AuthorizeSecurityGroupIngress)
              │
              ▼
        EventBridge  (pattern match on eventName)
              │
              ▼
      Lambda: remediation
         ├──► EC2   revoke_security_group_ingress
         ├──► DynamoDB   put_item (audit record)
         └──► SNS   publish → email alert

API Gateway (GET /logs) → Lambda: logs API → DynamoDB scan
```

### Services

| Service | Role |
|---|---|
| CloudTrail | Captures the `AuthorizeSecurityGroupIngress` API call |
| EventBridge | Filters events and triggers remediation |
| Lambda | Evaluates the rule, remediates, persists, notifies |
| EC2 | Target of the remediation |
| DynamoDB | Immutable audit log keyed by CloudTrail event ID |
| SNS | Email delivery to the security contact |
| API Gateway | Read-only HTTP endpoint for the audit log |

## How it works

1. A user adds an inbound rule allowing SSH from `0.0.0.0/0`.
2. CloudTrail records the API call and publishes it to the default event bus.
3. An EventBridge rule matches on `source: aws.ec2` and `eventName: AuthorizeSecurityGroupIngress`, and invokes the remediation Lambda.
4. The function parses the CloudTrail payload, checks whether any rule opens port 22 to the world, and if so:
   - calls `revoke_security_group_ingress` to remove it,
   - writes an audit record (event ID, timestamp, actor ARN, security group, action taken),
   - publishes an alert to SNS.
5. A second Lambda, behind API Gateway, exposes the audit log as JSON at `GET /logs`.

End-to-end latency is dominated by CloudTrail delivery (typically 2–5 minutes); Lambda execution itself takes under a second.

## Repository layout

```
src/
  remediation_lambda.py       # detection and remediation
  logs_api_lambda.py          # read-only audit log API
infra/
  eventbridge-pattern.json    # EventBridge rule pattern
  iam-policy-remediation.json # execution role for the remediation function
  iam-policy-logs-api.json    # scoped-down role for the logs API function
  iam-policy-hardened.json    # least-privilege variant of the remediation role
docs/screenshots/
```

## Deployment notes

Both functions run on Python 3.13 with a 30 second timeout. Environment variables:

| Function | Variable | Value |
|---|---|---|
| remediation | `TABLE_NAME` | DynamoDB table name |
| remediation | `SNS_TOPIC_ARN` | ARN of the alert topic |
| logs API | `TABLE_NAME` | DynamoDB table name |

The DynamoDB table uses `EventId` (String) as its partition key, on-demand capacity. The SNS email subscription must be confirmed before alerts are delivered. CloudTrail needs a trail logging management events (read and write) for EventBridge to receive the API calls.

## Results

Screenshots in `docs/screenshots/` show the full chain: the EventBridge pattern, the SNS alert email, the security group with the rule removed, the audit records in DynamoDB, the JSON response from `/logs`, and the CloudWatch execution log.

Sample audit record:

```json
{
  "EventId": "3383125a-9bb5-4ebb-b4b7-69f587362e15",
  "Timestamp": "2026-08-20T10:04:08Z",
  "UserARN": "arn:aws:iam::<account-id>:root",
  "SecurityGroupId": "sg-0xxxxxxxxxxxxxxxx",
  "ActionTaken": "Revoked SSH from 0.0.0.0/0"
}
```

## Design notes and known limitations

**IAM scope.** Three policy documents are included, and they aren't all what was deployed. `iam-policy-remediation.json` is the working execution role for the remediation function — it uses `"Resource": "*"` for all four permissions. `iam-policy-hardened.json` is a least-privilege rewrite of it, narrowing `dynamodb:PutItem` and `sns:Publish` to specific ARNs; `ec2:RevokeSecurityGroupIngress` has to stay wildcard, since the target security group isn't known ahead of time. The logs API function was deployed with the AWS managed `AmazonDynamoDBReadOnlyAccess` policy, which grants read access to every table in the account; `iam-policy-logs-api.json` is the scoped-down replacement, allowing only `dynamodb:Scan` on the audit table.

**Unauthenticated API.** `GET /logs` is public and returns IAM ARNs and security group IDs. A production deployment would put a JWT authorizer or IAM auth in front of it.

**Full table scan.** The logs endpoint uses `scan()`, which reads the entire table on every request. Fine at this scale; a GSI on timestamp with `query()` would be the right fix as the table grows.

**IPv6 not covered.** Detection matches `0.0.0.0/0` only. A rule opening SSH to `::/0` would pass through undetected.

**Fixed remediation target.** The function revokes tcp/22 from `0.0.0.0/0` rather than the exact rule it detected. Adequate here, but a more general version would revoke precisely what CloudTrail reported.

**Console-provisioned.** Everything was deployed manually. Rebuilding this as Terraform is the natural next step and would make the whole stack reproducible.

## Cost

Runs entirely within AWS always-free allowances for Lambda, DynamoDB, SNS, and EventBridge. The first CloudTrail trail with management events is free. The only measurable costs are S3 storage for trail logs and, if enabled, an SSE-KMS customer-managed key.