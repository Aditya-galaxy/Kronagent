# Aegis

**Autonomous AI threat-defense for enterprise networks — with guardrails you can audit.**

Aegis is an AI-native security platform built as a team of specialist agents: it ingests live findings from multi-cloud and cluster environments, triages and investigates them, synthesizes an incident assessment, preserves forensic evidence, and executes containment — with **graduated autonomy**, not blanket automation. Every decision is gated by a deterministic policy engine, every action is planned and logged before it runs, destructive actions always wait for a human, and the entire trail is a tamper-evident, hash-chained audit log.

Most "AI SOC" tools stop at investigation. Aegis executes — but only as much
autonomy as it has earned.

```bash
./demo.sh          # see it work, end to end, in your terminal
```

---

## Why it's built this way

The pitch for autonomous security response is easy; the trust model is the
hard part. Aegis's answer is **earn-trust, graduated autonomy**:

- **Safe by default.** On a cold start, the auto-execute allowlist is empty.
  Every containment action requires human approval until an operator
  explicitly promotes it — and that promotion is itself audited (who, when,
  why).
- **The policy engine is the hard ceiling, not a suggestion.** Actions are
  classified by reversibility and blast radius. Destructive or wide-blast
  actions (terminate an instance, delete a pod, scale a deployment to zero)
  are *structurally* incapable of running unattended — promoting one to the
  allowlist by mistake has no effect; the classification table wins.
- **LLMs reason, they never act.** Every agent's output schema is
  constructed so it cannot express a containment target or action class.
  Targets always come from the normalized finding data, never from a model —
  so a prompt-injection payload in telemetry cannot redirect an action onto
  an attacker-chosen resource.
- **Nothing is invisible.** Every decision — triage, policy, containment,
  approval, governance, forensics — is one entry in an append-only,
  SHA-256-chained audit log. Editing a past record breaks verification of
  every record after it. This is what makes an autonomous response
  defensible instead of a black box (and maps directly onto EU AI Act
  Article 12 automatic logging and Article 14 human oversight).

See [`agent-team-architecture.md`](agent-team-architecture.md) for the full
design rationale, and [`research.md`](research.md) for the market/competitive
analysis behind these choices.

---

## The agent team

| Agent | Type | Role |
|---|---|---|
| **Triage** | LLM | Is this finding a real, actionable threat? |
| **Threat Intelligence** | LLM | Maps the finding to MITRE ATT&CK; assesses indicators of compromise |
| **Investigation / Correlation** | LLM, with memory | Is this part of a larger campaign? Correlates against recent findings |
| **Incident Commander** | LLM | Synthesizes the above into one narrative, a priority (P1–P4), and an escalation decision |
| **Forensics** | Deterministic | Preserves evidence (EBS snapshots, pod logs/manifests) with chain of custody — *before* containment can destroy it |

Every LLM agent is purely **advisory**: it enriches the incident record and
the human's approval context, and never touches the policy decision. Only two
layers can cause a side effect — the deterministic **policy engine** (decides
whether an action may run) and **containment** (executes it, or doesn't).

```
Finding (AWS GuardDuty or Kubernetes audit event, normalized)
        │
        ▼
  Triage ──▶ Threat Intel ──▶ Correlation ──▶ Incident Commander      (LLM, advisory)
        │
        ▼
  Forensics (evidence + chain of custody, before containment)         (deterministic)
        │
        ▼
  Policy Engine → Containment → Approval → Audit                      (deterministic + human)
```

---

## What it actually does

- **Multi-provider detection.** AWS (GuardDuty findings — IAM/EC2) and
  Kubernetes (audit events — pods/nodes/deployments) normalize into one
  provider-neutral `Finding` type and flow through the identical pipeline.
  Adding a third source (Azure Defender, GCP SCC, an in-house detector) is a
  new module in `aegis/providers/` plus a registry entry — nothing else
  changes.
- **Live ingestion.** GuardDuty → EventBridge → SQS, long-polled with
  at-least-once, ack-after-process delivery — a crash mid-processing
  redelivers the finding rather than losing it.
- **Real containment, planned before it runs.** Every action — disable an
  IAM key, isolate an instance/pod, block an IP, cordon a node — computes its
  exact API calls and rollback plan first, always, whether it executes,
  waits for approval, or is blocked.
- **Human approval that happens before the side effect**, not a retrospective
  log — reviewed with the full context (triage verdict, ATT&CK mapping,
  campaign correlation, evidence collected) and executed through the same
  path an autonomous action would take.
- **Governance with an audit trail.** Promoting an action class to
  autonomous execution is a CLI command, not an environment-variable edit —
  it's persisted, takes effect immediately (no restart), and is
  hash-chained into the audit log.

---

## Quickstart

```bash
python3 -m pip install -r requirements.txt
cp .env.example .env        # add GEMINI_API_KEY for LLM-enriched triage (optional — degrades gracefully)

python3 run_slice.py                                   # replay both providers' sample findings
python3 run_slice.py kubernetes samples/k8s_audit_events.json   # replay one provider

python3 promote.py list                                 # inspect the auto-execute allowlist
python3 approve.py list                                 # inspect pending human approvals
python3 run_compliance_report.py                        # generate EU AI Act Article 12/14 report
python3 run_compliance_report.py --markdown-output rep.md # export a styled Markdown manifest

```

Everything above runs in **dry-run** by default (`AEGIS_DRY_RUN=true`) — no
cloud or cluster is touched. Findings are read from `samples/` with no AWS
account required.

### Live terminal demo

```bash
./demo.sh                        # interactive — press Enter between acts
AEGIS_DEMO_AUTO=1 ./demo.sh       # hands-off — auto-advances (for recording)
```

A five-act narrated walkthrough driving the **real CLIs**, no mocks: safe
defaults → cross-provider detection with graduated autonomy → earning trust
live (no restart) → human approval before execution → tamper-evident audit
(including a live tamper-detection demonstration). If the local SQS testbed
is installed, it also runs the *live* async ingestion path against a real
queue.

### Live SQS ingestion — no AWS account needed

```bash
python3 -m pip install -r testbed/requirements.txt
python3 testbed/sqs_emulator.py serve            # starts a local SQS emulator + streams sample findings in

# in another shell, using the endpoint/queue URL it prints:
export AEGIS_SQS_ENDPOINT_URL=http://localhost:5001
export AEGIS_SQS_QUEUE_URL=<printed queue URL>
python3 run_slice.py                             # long-polls and processes findings live
```

See [`testbed/README.md`](testbed/README.md) for the full setup, including the
Docker/ElasticMQ alternative and the reasoning behind choosing moto over
LocalStack.

### Governance — promoting an action class to autonomy

```bash
python3 promote.py add disable_access_key \
  --by alice --reason "30 days incident-free; reversible, single-credential blast radius"

python3 run_slice.py    # disable_access_key now auto-executes (still dry-run); destructive actions stay gated
```

### Approving a gated action

```bash
python3 approve.py list
python3 approve.py approve <request-id> --by alice --reason "confirmed compromise; isolate for forensics"
```

### Going live against real infrastructure

```bash
export AEGIS_DRY_RUN=false
export AEGIS_QUARANTINE_SG_ID=sg-...        # required for EC2 isolation
export AEGIS_QUARANTINE_NACL_ID=acl-...      # required for BLOCK_IP (EC2 Network ACL)
export AEGIS_DB_PATH=aegis.db               # optional: sqlite database for persistent store/memory
export AEGIS_KUBECONFIG=/path/to/kubeconfig # required for Kubernetes containment
export AEGIS_SQS_QUEUE_URL=https://sqs...   # your real GuardDuty -> EventBridge -> SQS queue
```

Only action classes present in the (audited, `promote.py`-managed) allowlist — and classified reversible/single-resource by the policy engine — will ever execute unattended. Everything else routes to `approve.py` regardless of `AEGIS_DRY_RUN`. Persistent storage can be enabled by specifying `AEGIS_DB_PATH` pointing to a SQLite database file, transitioning the approvals queue and correlation memory from file-based/in-memory scopes. See [`deploy/README.md`](deploy/README.md) for the AWS IAM policy and SQS/EventBridge wiring.

---

## Project layout

```
aegis/
  model.py            provider-neutral Finding / ResourceRef
  schemas.py           action taxonomy, triage/policy/outcome/audit types
  providers/
    aws.py              GuardDuty normalization + IAM/EC2 containment
    k8s.py               Kubernetes audit normalization + pod/node containment
  triage.py            deterministic action-mapping + LLM triage
  intel.py             Threat Intelligence Agent (MITRE ATT&CK)
  correlation.py       Investigation / Correlation Agent (+ campaign memory)
  commander.py         Incident Commander Agent (synthesis + escalation)
  forensics.py         Forensics Agent (evidence + chain of custody)
  policy.py            graduated-autonomy decision engine
  allowlist.py         audited, live-reloadable earn-trust store
  containment.py       provider-agnostic execution dispatch
  approvals.py         human approval workflow (supports SQLite/JSON)
  audit.py             hash-chained, tamper-evident audit log
  compliance.py        EU AI Act compliance reporting engine
  ingestion.py         file replay + live SQS ingestion
  config.py            all safety-critical settings (fail-safe defaults)

run_slice.py           runnable entry point
promote.py             earn-trust governance CLI
approve.py             human approval CLI
run_compliance_report.py  compliance reporting CLI
demo.sh                narrated live terminal demo

testbed/               local SQS emulator (no AWS account, no Docker)
deploy/                IAM policies, EventBridge/SQS wiring docs
samples/                real-schema sample findings (AWS + Kubernetes)
tests/                 176 tests, offline, ~2s
```

---

## Testing

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m pytest -q
```

176 tests, fully offline (no network, no cloud/cluster credentials, no LLM calls), running in a couple of seconds. Coverage highlights: the policy engine's safety ceiling (destructive actions proven to never auto-execute, even if allowlisted), the audit log's tamper-evidence (mutation-tested, not just asserted), the approval-provider round-trip, forensics-before-containment ordering (mutation-tested), live ingestion against a real SQS server, SQLite-backed storage persistence, and EU AI Act compliance report generation.

---

## Documentation

- [`agent-team-architecture.md`](agent-team-architecture.md) — why each agent is (or isn't) an LLM, and the safety envelope every agent operates inside
- [`research.md`](research.md) — market landscape, competitive analysis, and the strategic thesis
- [`deploy/README.md`](deploy/README.md) — IAM policy, EventBridge/SQS wiring for a real AWS deployment
- [`testbed/README.md`](testbed/README.md) — local SQS emulation, and why moto over LocalStack
- [`SECURITY.md`](SECURITY.md) — vulnerability reporting

---

## Status

This is a functional vertical slice. Detection, triage, policy, approval, governance, and audit are real and tested end-to-end against both AWS and Kubernetes. Containment execution contains fully implemented, live client code paths for key containment actions: `BLOCK_IP` (AWS Network ACLs), `REVOKE_ROLE_SESSIONS` (AWS IAM), and `ISOLATE_POD` (Kubernetes NetworkPolicies). The platform also supports database persistence for campaign memory and approvals, and features automated EU AI Act compliance report exporting. Other actions run in plan-only/dry-run unless custom adapters are added.

---

## Roadmap & Future Work

Based on Aegis's design milestones (detailed in `aegis_next_steps.md`), the following architectural and security developments are planned:

### 1. Staging Testbed (Minikube + LocalStack)
*   **Simulation Environment:** Construct a local cluster and cloud sandbox environment (Minikube/Kind + LocalStack) to dry-run containment actions against real simulated resources before promotion to staging cloud accounts.

### 2. Distributed Workers & Scaling
*   **Task Queues:** Decouple ingestion from orchestration by introducing a distributed worker queue architecture (e.g., Celery/async worker pools) to process telemetry streams concurrently.

### 3. Adversarial AI Hardening
*   **Sanitization Layer:** Put a preprocessing layer in place to sanitize IP and log headers before feeding prompts to LLM agents, shielding the triage/intel processes from prompt injection jailbreaks.
*   **KMS-Signed Forensics:** Secure the forensic custody hashes by signing them with an AWS KMS or HSM private key, allowing immediate detection of post-record tampering.

### 4. Continuous Red Teaming
*   **Benign Alert Drift:** Introduce a simulator that occasionally fires fake alerts to verify the policy engine, allowlist, and operator approval routing remain correctly calibrated and live.

