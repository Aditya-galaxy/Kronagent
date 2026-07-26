# Kronagent — Future Plan

*Compiled 2026-07-22. Grounded in 2026 sources (cited inline). Companion to
`research.md` (market/strategy) and `agent-team-architecture.md` (technical
design). This is a phased plan, not a set of commitments — each phase is
independently valuable and ordered by leverage toward the outcome in
`research.md`: a monetizable, differentiated enterprise AI-SOC platform.*

---

## Where we are (honest baseline)

The capability roadmap is essentially built: the full agent team (triage,
threat-intel, correlation, incident commander, forensics), a graduated-autonomy
policy engine, live containment execution (Kubernetes validated against a real
Kind + Calico cluster; AWS code paths live but not yet run against a real
account), SQLite-backed persistence, an EU AI Act Article 12/14 compliance
exporter, prompt-injection sanitization, KMS/RSA-signed forensic custody,
parallel workers, continuous red-team drift simulation, and — newest —
authenticated, RBAC-gated operator identity on approvals and governance.

**The frontier has shifted from *capability* to *product* and *proof*.** The
engine works; the gaps are now (1) proving it works with measured rigor, and
(2) the enterprise-readiness layer that stands between a compelling CLI demo and
something an enterprise can buy, operate, and trust at scale.

Two known defects to clear first (found during analysis, not yet fixed):
- **Sanitization mutates the containment target.** `sanitize_finding` rewrites
  resource IDs that drive containment targeting, not just the LLM prompt — IAM
  principals with `@ + = ,` (valid IAM chars) get silently altered. Fix: sanitize
  the LLM-facing copy only; the containment target must stay verbatim finding
  data. (This partially undermines the architecture's own "targets come from
  deterministic data, never mutated" guarantee.)
- **Doc drift.** The README's roadmap still lists now-completed items as planned.

---

## Phase 1 — Prove it: a measured evaluation harness *(highest leverage)*

**Why first.** You cannot responsibly sell *autonomous* response without measured
precision/recall — and the research shows a specific, unclaimed gap. Rigorous
benchmarks now exist: **SIR-Bench** (794 test cases across 129 anonymized
incident patterns, scoring investigation depth) and **OpenSec** (agent
calibration under adversarial evidence). Reported bars to beat: Microsoft's
Copilot Guided Response hits ~0.87 macro-F1; a research SIR agent hit 97.1% true-
positive detection / 73.4% false-positive rejection versus Tier-2 human analysts
at 85–90% / 70–80%.

The wedge: *"existing evaluations rarely measure whether agents make [the false-
positive] problem better or worse **when given authority to act**."*
([AI-Augmented SOC survey](https://www.mdpi.com/2624-800X/5/4/95)) That is exactly
what Kronagent does that investigation-only tools don't — so lead there.

**Build:**
- A labeled corpus of attack + benign traces (extend `samples/` + the drift
  simulator; align to the public benchmarks where possible).
- Metrics that measure the *whole pipeline decision*, not just triage: triage
  precision/recall/F1 **and** containment-decision correctness (did the policy
  route the right action to auto/approval/block?) and a false-positive-under-
  authority score — the metric the market isn't reporting.
- A `run_eval.py` that produces a scored report, wired into CI as a regression
  gate so capability changes can't silently degrade accuracy.
- Account for label noise: SOC analysts disagree 10–20% on labels, which caps
  classical metrics — report confidence intervals, not point estimates.

**Payoff:** turns "trust us, it's accurate" into a number, defensible in a sales
or fundraising conversation, and stakes a claim on the metric competitors avoid.

*Sources:* [SIR-Bench](https://arxiv.org/html/2604.12040v1) ·
[OpenSec](https://arxiv.org/pdf/2601.21083) ·
[AI-Augmented SOC survey](https://www.mdpi.com/2624-800X/5/4/95) ·
[Autonomous SOC guide — UnderDefense](https://underdefense.com/blog/autonomous-soc/)

---

## Phase 2 — Enterprise readiness (the procurement gate)

2026 procurement research is blunt: platforms that can't meet these **do not pass
procurement**, regardless of how good the engine is
([D3](https://d3security.com/blog/ai-soc-platforms-2026/),
[Conifers CISO guide](https://www.conifers.ai/blog/the-enterprise-ai-soc-a-cisos-guide-from-pilot-to-production-in-2026)).

| Requirement | Kronagent today | Work |
|---|---|---|
| **SSO (SAML/OIDC)** — *"username/password only will not pass procurement"* | Identity + RBAC shipped; `IdentityProvider` is the SSO seam | Implement an OIDC provider behind the existing seam — no caller change |
| **RBAC** | ✅ Done (viewer/approver/admin) | Extend roles as customers require |
| **Multi-tenancy / business-unit isolation** | Single-tenant | Tenant-scoped stores, audit, allowlist; kernel-level isolation for the MSSP channel (`research.md` flagged MSSP as a distribution path) |
| **SIEM export + OCSF normalization** | Provider-neutral `Finding` (OCSF-adjacent already) | Map `Finding`/audit to **OCSF**, export to Splunk/Sentinel. OCSF is *the* 2026 normalization standard; ~30–40% of integration effort is schema mapping, and this is where the audit trail becomes a SOC-2-exportable artifact |
| **Case management + analyst console** | CLI only | A web console for the approval queue, incident view, and audit search — the single biggest gap between "engine" and "product." Analysts must search months of history under incident pressure |
| **ChatOps approvals** | CLI only | Slack/Teams approval flow so the human-in-the-loop step meets analysts where they work |

**Recommended first slice:** OCSF-align the audit/finding schema and ship a SIEM
export. It's high-credibility (a recognized standard), it makes the compliance
audit trail *exportable* (a SOC-2 Type 2 requirement:
*"whether logs can be exported to your SIEM"*), and it's non-disruptive
integration — the top evaluation criterion.

*Sources:* [OCSF inflection point — Databahn](https://www.databahn.ai/blog/what-is-ocsf-and-why-normalize-security-data-now) ·
[OCSF for vendors — Synqly](https://www.synqly.com/ocsf-explained-cybersecurity-integration-standards/) ·
[AI SOC for enterprise — UnderDefense](https://underdefense.com/blog/ai-soc-for-enterprise/)

---

## Phase 3 — Real cloud validation & graduated production rollout

The Kubernetes containment path is validated live (Kind + Calico, traffic
provably blocked). The AWS path has live code that has **never run against a real
account**. Close it:

- Provision a throwaway AWS account; validate `BLOCK_IP` (NACL), IAM actions, and
  instance isolation execute *and roll back* for real, in a sandbox.
- Codify a **graduated production rollout** methodology: dry-run → approval-gated
  live → promote one reversible action class at a time, each with a measured
  soak period (ties directly to the earn-trust allowlist and the Phase 1 metrics).
- Chaos/rollback drills: prove every containment action's rollback actually
  restores state.

**Payoff:** converts "architecturally sound" into "demonstrably executes on real
infrastructure" — the minimum bar for a production reference customer.

---

## Phase 4 — Secure the agent team itself

Bessemer calls securing AI agents *"the defining cybersecurity challenge of
2026"* ([Bessemer](https://www.bvp.com/atlas/securing-ai-agents-the-defining-cybersecurity-challenge-of-2026)).
An autonomous responder holding production write-credentials is itself a
high-value target and an insider-risk vector.

- **Least-privilege, per-action scoped credentials.** The platform's own IAM is
  now crown jewels — scope each containment action to the narrowest possible
  grant, issued just-in-time, not a standing broad role.
- **Harden the injection surface further.** Sanitization exists but has the
  target-mutation bug (Phase 0); after fixing, red-team the agents specifically —
  extend the drift simulator into an adversarial-input suite that tries to make
  an agent mis-triage or mis-escalate.
- **Agent-to-agent trust & non-repudiation.** Extend the identity/audit model
  from human operators to the agents themselves — every agent action already
  audited; sign agent decisions the way custody records are signed.
- **Kill-switch & blast-radius drills** under adversarial conditions.

---

## Phase 5 — Detection depth & more substrates

The provider abstraction makes this additive (a module + registry entry):

- **More sources:** Azure Defender, GCP Security Command Center, EDR
  (CrowdStrike/SentinelOne), an in-house syslog/Falco detector.
- **Threat-intel feeds:** STIX/TAXII ingestion so the threat-intel agent
  correlates against live IOC feeds, not just its own reasoning.
- **Native anomaly detection** (optional): today Kronagent consumes upstream
  detections; a lightweight native detector would reduce dependence on
  GuardDuty/Falco.

---

## Recommended sequencing

```
Phase 0  (days)    Fix the two known defects; merge identity/RBAC.
Phase 1  (weeks)   Evaluation harness — the credibility unlock. Do this first.
Phase 2  (weeks)   OCSF + SIEM export first, then SSO, then console, then multi-tenancy.
Phase 3  (weeks)   Real AWS validation once a sandbox account exists (parallelizable).
Phase 4  (ongoing) Agent-security hardening — begin alongside Phase 2.
Phase 5  (ongoing) New providers as customers demand them.
```

**The through-line to monetization** (`research.md`): the differentiator is
*audited execution + graduated autonomy + compliance*, sold tiered-by-autonomy
and through the MSSP channel, with the EU AI Act as a time-sensitive hook.
Phase 1 makes the differentiator *measurable*; Phase 2 makes it *buyable*;
Phase 3 makes it *provable on real infrastructure*; Phase 4 keeps it *trustworthy*
as the attack surface it introduces grows.

---

## Sources

- [AI-Augmented SOC: Survey of LLMs and Agents — MDPI](https://www.mdpi.com/2624-800X/5/4/95)
- [SIR-Bench: Investigation Depth in Security Incident Response Agents — arXiv](https://arxiv.org/html/2604.12040v1)
- [OpenSec: Incident Response Agent Calibration Under Adversarial Evidence — arXiv](https://arxiv.org/pdf/2601.21083)
- [Autonomous SOC Guide — UnderDefense](https://underdefense.com/blog/autonomous-soc/)
- [The Enterprise AI SOC: A CISO's Guide From Pilot to Production — Conifers](https://www.conifers.ai/blog/the-enterprise-ai-soc-a-cisos-guide-from-pilot-to-production-in-2026)
- [Best AI SOC Platforms 2026 — D3 Security](https://d3security.com/blog/ai-soc-platforms-2026/)
- [AI SOC for Enterprise — UnderDefense](https://underdefense.com/blog/ai-soc-for-enterprise/)
- [What Is OCSF, and Why Normalize Security Data Now — Databahn](https://www.databahn.ai/blog/what-is-ocsf-and-why-normalize-security-data-now)
- [OCSF Explained for Vendors — Synqly](https://www.synqly.com/ocsf-explained-cybersecurity-integration-standards/)
- [Securing AI agents: the defining cybersecurity challenge of 2026 — Bessemer](https://www.bvp.com/atlas/securing-ai-agents-the-defining-cybersecurity-challenge-of-2026)
