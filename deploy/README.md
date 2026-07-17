# Aegis — AWS deployment & least-privilege wiring

This directory holds the AWS-side prerequisites for running Aegis against a real
account. The design principle is **least privilege for the responder itself**:
Aegis's own credentials must be able to perform *only* the specific containment
actions the executor makes, so a compromised or misbehaving agent has a bounded
blast radius. `aegis-iam-policy.json` grants exactly those calls and nothing
else.

> The policy is **apply-ready** (valid IAM grammar, no annotations that AWS
> would reject). All the "why" lives here in the README.

## 1. Prerequisites to provision once (by a human, out of band)

Aegis references two pre-provisioned resources by id — it never creates them, so
it never needs `create-security-group` / `create-network-acl` privileges.

| Resource | Purpose | Wire into Aegis via |
|---|---|---|
| **Quarantine security group** — a deny-all SG (no ingress, no egress) in each VPC you protect | `ISOLATE_INSTANCE_SG` swaps a compromised instance into this SG, cutting all traffic while preserving the instance for forensics | `AEGIS_QUARANTINE_SG_ID=sg-xxxx` |
| **Quarantine NACL** — a network ACL whose entries Aegis manages | `BLOCK_IP` adds a deny entry for an attacker IP here; rollback removes it | `QUARANTINE_NACL_ID` in the policy ARN |

## 2. Substitute the placeholders in `aegis-iam-policy.json`

| Placeholder | Replace with |
|---|---|
| `ACCOUNT_ID` | your 12-digit AWS account id |
| `REGION` | the operating region, e.g. `us-east-1` (must match `AWS_REGION` / `AEGIS_QUARANTINE_SG_ID`'s region) |
| `QUARANTINE_NACL_ID` | the real `acl-xxxx` id of the quarantine NACL |

```bash
sed -i '' \
  -e 's/ACCOUNT_ID/123456789012/g' \
  -e 's/REGION/us-east-1/g' \
  -e 's/QUARANTINE_NACL_ID/acl-0abc123/g' \
  deploy/aegis-iam-policy.json
```

## 3. Attach the policy to a dedicated Aegis principal

Give Aegis its **own** IAM role/user — never reuse an existing operator or CI
identity. Prefer a role assumed via short-lived credentials (STS) over a
long-lived access key.

```bash
aws iam create-policy \
  --policy-name AegisContainmentLeastPrivilege \
  --policy-document file://deploy/aegis-iam-policy.json

# then attach the returned ARN to the Aegis role/user
```

## 4. Statement-by-statement rationale

| Sid | Action(s) | Aegis action class | Scoping notes |
|---|---|---|---|
| `DisableAndReenableAccessKeys` | `iam:UpdateAccessKey` | `DISABLE_ACCESS_KEY` (+ reactivate rollback) | `iam:UpdateAccessKey` has **no** resource-level condition for the key id, so it is scoped to `user/*` in this account only. |
| `QuarantineDenyAllInlinePolicyOnly` | `iam:PutUserPolicy`, `iam:DeleteUserPolicy` | `ATTACH_DENY_ALL_TO_PRINCIPAL` (+ rollback) | `Condition` pins these to **exactly** the inline policy name `aegis-quarantine-deny-all` — they cannot touch any other inline policy. |
| `RevokeRoleSessionsInlinePolicyOnly` | `iam:PutRolePolicy`, `iam:DeleteRolePolicy` | `REVOKE_ROLE_SESSIONS` (+ rollback) | Same single-policy-name pin (`aegis-revoke-sessions`). Classified **destructive** in the policy engine → never auto-executes. |
| `ReadInstanceStateForRollbackCapture` | `ec2:DescribeInstances` | supports `ISOLATE_INSTANCE_SG` | Read-only. Captures the instance's current SGs so rollback restores the exact original set. `ec2:DescribeInstances` does not support resource-level permissions (AWS limitation) → `Resource: *`. |
| `IsolateInstanceIntoQuarantineSG` | `ec2:ModifyInstanceAttribute` | `ISOLATE_INSTANCE_SG` | Region-scoped. AWS can't condition this on the *target* SG, so Aegis enforces the deny-all quarantine SG in code (`AEGIS_QUARANTINE_SG_ID`). |
| `BlockIpAtQuarantineNacl` | `ec2:CreateNetworkAclEntry`, `ec2:DeleteNetworkAclEntry` | `BLOCK_IP` (+ rollback) | Pinned by **ARN** to the single quarantine NACL. Aegis cannot modify any other NACL. |
| `TerminateInstancesInRegion` | `ec2:TerminateInstances` | `TERMINATE_INSTANCE` | Irreversible, destructive, always human-approved. **Consider deleting this statement** until you actually need the terminate class — least privilege means granting it only when used. |

## 5. Live ingestion: GuardDuty → EventBridge → SQS

Aegis reads live findings by long-polling an SQS queue. Set `AEGIS_SQS_QUEUE_URL`
and `run_slice.py` switches from file replay to the live source automatically;
unset it to fall back to replaying `samples/`.

```
AEGIS_SQS_QUEUE_URL=https://sqs.us-east-1.amazonaws.com/123456789012/aegis-findings
AWS_REGION=us-east-1
```

**Wiring (provision once):**

1. **SQS queue** `aegis-findings` with:
   - **visibility timeout ≥ 60s** — must exceed the max per-finding processing
     time (LLM triage + containment). A message is invisible while Aegis
     processes it and is deleted only after it's fully handled and audited
     (ack-after-process); too short a timeout causes double-processing.
   - a **redrive policy → dead-letter queue** `aegis-findings-dlq` with
     `maxReceiveCount` ~5. Messages that don't parse as GuardDuty findings are
     **left in place, not deleted**, so SQS moves them to the DLQ instead of the
     pipeline losing them. Without a DLQ, a poison message redelivers forever.
2. **EventBridge rule** matching GuardDuty findings, targeting the queue:
   ```json
   { "source": ["aws.guardduty"], "detail-type": ["GuardDuty Finding"] }
   ```
   Add an SQS queue policy allowing `events.amazonaws.com` to `sqs:SendMessage`
   to the queue ARN. (A GuardDuty → EventBridge → **SNS** → SQS topology also
   works — the consumer unwraps the SNS `Notification` envelope automatically.)
3. **Attach `aegis-sqs-ingestion-policy.json`** to the Aegis principal — a
   read-only grant (`ReceiveMessage`/`DeleteMessage`/`GetQueueAttributes`) scoped
   to the one queue ARN. This is separate from the containment policy: ingestion
   is read-only and touches only the queue; containment is write and touches AWS
   infrastructure. Keeping them separate keeps each grant minimal.

**Delivery semantics:** at-least-once. On a crash mid-processing the message
reappears after the visibility timeout and is re-processed — a finding is never
silently lost. Re-processing is safe because containment actions are idempotent
and approval-gated.

## 6. Honest limitations

- **Three actions can't be fully resource-conditioned by AWS** (`iam:UpdateAccessKey`,
  `ec2:DescribeInstances`, and the target-SG on `ec2:ModifyInstanceAttribute`).
  Where the IAM grammar can't express the constraint, Aegis enforces it in code
  and in the policy engine — defense in depth, but worth knowing the boundary.
- **This policy is the containment executor's grant only.** The Aegis host also
  needs read access to its telemetry source (GuardDuty → EventBridge → SQS);
  that is a separate, read-only policy not included here.
- **Rotate to STS/short-lived credentials for production.** A static access key
  with this policy is still a high-value target; scope it with an SCP and a
  permissions boundary, and prefer role assumption.
