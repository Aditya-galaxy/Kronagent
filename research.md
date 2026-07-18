# Aegis — Market Research & Strategic Direction

*Compiled 2026-07-18. Grounded in live web research (sources cited throughout), not
assumed knowledge — this space has moved fast enough in the last 18 months that
stale priors would mislead.*

---

## 1. The one-paragraph thesis

The AI-SOC market is real, funded, and growing fast — but nearly every well-funded
competitor stops at **investigation**, not **execution**. The "industry consensus"
architecture that's emerging in 2026 — autonomous triage, approval-gated containment,
human-executed high-impact remediation — is *exactly* what Aegis already is, not
something we'd need to pivot toward. Combined with an EU AI Act enforcement deadline
(Aug 2, 2026) that specifically rewards audited human oversight, there's a real,
timely wedge: **sell the audited execution layer that the investigation-only
incumbents don't have**, not a better triage bot.

---

## 2. Market sizing

| Segment | 2026 size | Trajectory | Source |
|---|---|---|---|
| SOAR (security orchestration/automation/response) | $2.22B | → $4.4B by 2030, 18.6% CAGR | [Mordor Intelligence](https://www.mordorintelligence.com/industry-reports/security-orchestration-automation-and-response-market) |
| AI-in-cybersecurity (broad) | ~$24.8B (2024 baseline) | → $146.5B by 2034 | via [Stellar Cyber](https://stellarcyber.ai/learn/top-10-agentic-soc-platforms/) |
| MSSP / SOC-as-a-Service | $14–15B | Growing fast, driven by mid-market adoption | via [Underdefense](https://underdefense.com/blog/ai-soc-for-mid-market/) |
| Agentic AI security funding (RSAC 2026 window alone) | $392M in 2 weeks | Accelerating; $3.6B total Crunchbase funding in category cited | [softwarestrategiesblog.com](https://softwarestrategiesblog.com/2026/03/28/agentic-ai-security-startups-funding-mna-rsac-2026/) |

**Read:** this isn't a speculative category. It's funded, it's growing double-digit
CAGR, and buyers are actively purchasing. The risk isn't "does this market exist" —
it's "can a new entrant differentiate against funded incumbents."

---

## 3. Competitive landscape

Pulled directly from a 2026 vendor comparison ([Underdefense](https://underdefense.com/blog/agentic-soc-platforms/)) plus pricing research:

| Vendor | Pricing | Execution model | Gap / weakness |
|---|---|---|---|
| **Dropzone AI** | ~$36K/yr for 4,000 investigations (~$9/investigation) | Fully autonomous **investigation**; no execution | No human fallback; investigation-only, not containment |
| **Prophet Security** | ~$50K/5,000 investigations (~$10 ea) + overage | Autonomous investigation, SIEM-agnostic | Same — investigation, not execution |
| **Radiant Security** | ~$1,188/yr referenced (mid-market flat-rate) | "Fully autonomous" triage/response, no playbooks needed | Early-stage (founded 2021), unproven at enterprise scale |
| **Torq HyperSOC** | Six-figure enterprise contracts | Fully agentic multi-agent mesh, Tier 1–3 | Needs an engineering-mature SOC to operate; not for mid-market |
| **Intezer** | Endpoint-based (undisclosed) | Deterministic + LLM, reproducible/auditable | Forensic depth over speed; smaller footprint |
| **CrowdStrike Charlotte AI** | Falcon add-on (undisclosed) | Fully agentic, Falcon-native | Ecosystem lock-in — weak outside Falcon stack |
| **SentinelOne Purple AI** | Tiered licensing add-on | Fully agentic, claims 338% 3yr ROI | Strongest value only inside Singularity ecosystem |
| **UnderDefense** | $11–15/endpoint/month | Semi-autonomous — AI investigates, humans own response | Positioned as best overall by its own comparison (bias noted) |

**The pattern that matters:** of eight vendors surveyed, the ones that claim "fully
autonomous" almost universally mean *autonomous investigation*, with execution either
absent or hand-waved. Only Torq and the big-platform players (CrowdStrike,
SentinelOne) claim real agentic execution — and both come with lock-in (into their
existing platform, or into an "engineering-mature SOC" prerequisite most mid-market
buyers don't have.

---

## 4. The actual strategic gap

Three independent research threads converged on the same finding:

**(a) The industry's own stated target architecture is graduated autonomy —
and we already built it.** From 2026 AI-SOC trend research:

> "The industry consensus has moved toward a tiered autonomy model rather than full
> automation: Triage and enrichment are autonomous (high volume, low risk),
> containment actions require human approval (medium risk), and remediation is
> human-executed (high impact)." — [Underdefense, AI SOC Trends 2026](https://underdefense.com/blog/ai-soc-automation/)

This is a description of Aegis's policy engine (`aegis/policy.py`) almost verbatim:
reversibility + blast-radius gate what auto-executes, everything else routes to a
human, high-impact/destructive actions are structurally incapable of running
unattended regardless of allowlist state. We didn't design toward a market gap after
the fact — the earn-trust model we built for safety reasons *is* the differentiated
product.

**(b) Regulation is about to make "audited human oversight" a compliance requirement,
not a nice-to-have.** The EU AI Act's high-risk system obligations become binding
**August 2, 2026** — weeks from now. Article 14 requires human oversight
"commensurate with risk and level of autonomy"; Article 12 requires automatic,
tamper-evident logging across the system's lifecycle.
([artificialintelligenceact.eu](https://artificialintelligenceact.eu/article/14/),
[Cloud Security Alliance](https://labs.cloudsecurityalliance.org/research/csa-research-note-eu-ai-act-high-risk-compliance-deadline-20/))

Aegis's hash-chained audit log and the promote/approve governance CLIs are close to
a literal implementation of what Article 12/14 compliance requires. Competitors
selling "fully autonomous, no human in the loop" containment are the ones with
compliance exposure here, not us.

**(c) The buyer who can't afford the incumbents is large and underserved.** A
mid-market org (200–2,000 employees) needing genuine 24/7 SOC coverage faces
$1.8M–$3.5M/year in-house, or 5–7 FTEs at ~$106–120K each just for headcount.
([sources](https://underdefense.com/blog/ai-soc-for-mid-market/)) This is exactly why
Dropzone/Prophet/Radiant exist and are growing — but they sell investigation speed,
not the thing that actually closes an incident (contained + rolled back +
audited execution). There's room to be "the execution layer" these buyers plug in
alongside — or instead of — an investigation-only tool.

---

## 5. Where Aegis stands against this landscape today

Honest inventory, not aspirational:

| Capability | Aegis today | Competitive read |
|---|---|---|
| Detection/triage (deterministic + LLM) | ✅ Real, tested, fast (~2s/call on `gemini-3.1-flash-lite`) | Table stakes — every competitor has this |
| Graduated-autonomy policy engine | ✅ Real, tested — reversibility/blast-radius gated | **This is the differentiator.** Matches the stated 2026 industry-consensus architecture that most competitors *don't* actually implement |
| Real containment execution (dry-run + live paths) | ✅ Real boto3 IAM/EC2 paths, concrete plan + rollback for every action | Rare — most "AI SOC" vendors stop before this |
| Audited approval workflow | ✅ Real, hash-chained, attributable | Aligns with EU AI Act Art. 12/14 — a live compliance angle competitors don't emphasize |
| Governance / earn-trust promotion CLI | ✅ Real, audited, live-reloadable | Not something I've seen any competitor describe explicitly |
| Multi-cloud / multi-source | 🟡 In progress — AWS done, Kubernetes provider being extracted now | Necessary to be credible outside AWS-only shops; none of the surveyed competitors are single-cloud, so this closes a real gap, doesn't create a new one |
| Live production execution (unattended, on a real account) | ⬜ Never run — blocked on a throwaway AWS account | The one thing standing between "architecturally sound" and "provably works" |
| Scale (Kafka-class ingestion, multi-tenant, SIEM integration) | ⬜ Not started | Needed for enterprise; not needed to validate the wedge |

**The honest gap:** everything above the execution layer is real and tested; nothing
has run unattended against live production yet. That's the next credibility
milestone, not a nice-to-have.

---

## 6. Monetization — is this something people will pay for, and how

**Yes, with high confidence** — the comparables above are actual paying customers at
actual price points, not speculative TAM math. Three live pricing models to weigh:

### Option A: Per-investigation / per-alert (Dropzone/Prophet model)
- ~$9–10 per investigation, packaged in blocks (e.g., $36–50K/yr for 4–5K investigations)
- **Pro:** Proven, buyers already understand it, easy to benchmark against
- **Con:** Prices the *triage* layer, which is now a commodity (every competitor has
  it) — doesn't capture the value of the part we actually do better (execution)

### Option B: Per-endpoint/month (UnderDefense model)
- $11–15/endpoint/month
- **Pro:** Scales predictably with customer size, familiar SaaS motion
- **Con:** Same commoditization problem — endpoint count doesn't track containment
  value delivered

### Option C: Tiered by autonomy level (recommended)
- **Free/cheap tier:** triage + investigation only (commodity — priced to acquire,
  not to make money, matching the market rate above)
- **Paid tier:** unlocks approval-gated containment — priced per action *proposed*
  (not executed), since the value is in the audited plan + rollback even before a
  human clicks approve
- **Premium tier:** unlocks autonomous execution for allowlisted action classes —
  priced at a premium, justified by the audit/compliance story (EU AI Act framing
  sells directly into this tier's buyer: CISO/compliance, not just SOC manager)
- **Pro:** Prices the actual differentiator; the free/cheap tier undercuts
  Dropzone/Prophet as a wedge, and the paid tiers monetize the part they don't have
- **Con:** More complex to sell; needs real reference deployments before enterprise
  buyers trust the premium tier

### Go-to-market channel
Given the mid-market cost gap ($1.8–3.5M/yr in-house SOC), the MSSP/MSP channel
($14–15B SOCaaS market, growing) is a credible path to distribution without a direct
enterprise sales motion — sell Aegis *to* MSSPs as their execution layer, not only
direct to end customers.

**Recommendation:** Option C (tiered by autonomy), sold both direct (compliance-driven
enterprise) and channel (MSSP), leading with the EU AI Act angle for the premium tier
specifically — it's a genuinely time-sensitive hook (enforcement in weeks, not years)
that most competitors aren't positioning around yet.

---

## 7. Real risks, stated plainly

- **Well-funded, fast-moving competitors.** Dropzone alone claims 300+ customers
  including UiPath, Zapier, Pipe. This is not an empty field — differentiation has to
  be real and demonstrable, not just claimed in a pitch deck.
- **Platform bundling risk.** CrowdStrike and SentinelOne can bundle "good enough"
  agentic response into platforms customers already buy, at effectively $0 marginal
  price. Aegis's cross-platform, non-lock-in positioning is a hedge against this, but
  only if the second/third provider (Kubernetes, then a second cloud) actually ships.
- **LLM cost unpredictability.** Multiple sources flag token/model cost as the "next
  major value challenge" for agentic SOC economics — every reasoning chain, every
  investigation, every re-triage burns tokens. We already made one real cost/latency
  decision here (switching triage to `gemini-3.1-flash-lite`); this needs to stay a
  first-class engineering concern, not an afterthought, as usage scales.
- **Zero live production runs to date.** Every claim about "real execution" is
  currently backed by dry-run tests and mocked AWS clients, not a live account. This
  is the single biggest gap between the pitch and provable fact, and should be closed
  before any external claim about autonomous execution is made to a prospect.

---

## 8. Recommended next moves (in order)

1. **Finish the Kubernetes provider extraction** (in progress) — this is the proof
   point for "not AWS-only," which every credible competitor already is.
2. **Get a throwaway AWS account and run one real, live, approval-gated execution
   end-to-end.** This converts "architecturally sound" into "demonstrably works,"
   which is the minimum bar for any customer conversation.
3. **Build a one-page comparison artifact** (Aegis vs. the table in §3) for
   fundraising/sales conversations — the "investigation-only vs. audited execution"
   framing is the sharpest, most defensible wedge found in this research.
4. **Lead early conversations with the EU AI Act angle** for any EU-exposed prospect
   — enforcement is weeks away, and almost no competitor in the survey above is
   positioning around it explicitly.

---

## Sources

- [Agentic AI security funding, RSAC 2026](https://softwarestrategiesblog.com/2026/03/28/agentic-ai-security-startups-funding-mna-rsac-2026/)
- [SOAR Market Size — Mordor Intelligence](https://www.mordorintelligence.com/industry-reports/security-orchestration-automation-and-response-market)
- [Top 10 Agentic SOC Platforms 2026 — Stellar Cyber](https://stellarcyber.ai/learn/top-10-agentic-soc-platforms/)
- [Agentic AI SOC Platforms comparison — Underdefense](https://underdefense.com/blog/agentic-soc-platforms/)
- [AI SOC Automation 2026 (tiered autonomy consensus) — Underdefense](https://underdefense.com/blog/ai-soc-automation/)
- [Dropzone AI pricing](https://www.dropzone.ai/pricing)
- [AI SOC for Mid-Market — Underdefense](https://underdefense.com/blog/ai-soc-for-mid-market/)
- [EU AI Act Article 14 — Human Oversight](https://artificialintelligenceact.eu/article/14/)
- [EU AI Act High-Risk Deadline — Cloud Security Alliance](https://labs.cloudsecurityalliance.org/research/csa-research-note-eu-ai-act-high-risk-compliance-deadline-20/)
