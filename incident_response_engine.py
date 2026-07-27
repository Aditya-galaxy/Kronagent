#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com
"""
Automated Incident Response Engine
AI-native, async multi-agent pipeline: Ingestion -> Triage -> Isolation -> Remediation.
Each of the Triage/Isolation/Remediation agents is a Claude tool-use call that
reasons about the alert and selects an action; a deterministic playbook is the
fallback path if the model is unavailable. Python 3.12+, pydantic v2, native
asyncio, Anthropic SDK.
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import sys
import uuid
from datetime import datetime, timezone
from typing import Literal

import anthropic
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s.%(msecs)03dZ %(message)s",
    datefmt="%H:%M:%S",
    stream=sys.stdout,
)
log = logging.getLogger("ir_engine")

# Claude model used by every LLM-driven agent in the pipeline.
MODEL = "claude-opus-4-8"


# --------------------------------------------------------------------------- #
# 1. Structured Telemetry & Validation
# --------------------------------------------------------------------------- #

class InfrastructureAlert(BaseModel):
    """Immutable, strictly validated telemetry record."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime
    source: Literal["cloud", "application", "endpoint"]
    severity: int = Field(ge=1, le=10)
    ioc_payload: dict
    resource_id: str = Field(min_length=1)

    @field_validator("resource_id")
    @classmethod
    def resource_id_not_blank(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("resource_id must not be blank")
        return v


class TriageResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    alert: InfrastructureAlert
    active_threat: bool
    matched_iocs: list[str]
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str


class IsolationAction(BaseModel):
    model_config = ConfigDict(frozen=True)

    resource_id: str
    action_type: Literal["security_group_lockdown", "container_termination", "gateway_ip_block"]
    detail: str
    executed_at: datetime


class RemediationAction(BaseModel):
    model_config = ConfigDict(frozen=True)

    resource_id: str
    action_type: Literal["container_restart", "patch_deployment", "image_rollback"]
    detail: str
    executed_at: datetime


# --------------------------------------------------------------------------- #
# 2. Async Ingestion Engine
# --------------------------------------------------------------------------- #

KNOWN_IOCS = {"185.220.101.7", "cve-2024-3400", "mimikatz.exe", "cobaltstrike-beacon"}

_SOURCES: tuple[Literal["cloud", "application", "endpoint"], ...] = (
    "cloud",
    "application",
    "endpoint",
)

_TEMPLATES = {
    "cloud": [
        {"provider": "aws-guardduty", "finding_type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration",
         "source_ip": "185.220.101.7"},
        {"provider": "aws-guardduty", "finding_type": "Recon:EC2/PortProbeUnprotectedPort", "source_ip": "10.0.4.12"},
        {"provider": "aws-guardduty", "finding_type": "CryptoCurrency:EC2/BitcoinTool.B!DNS", "source_ip": "10.0.9.3"},
    ],
    "application": [
        {"provider": "k8s-audit", "verb": "create", "object": "pods/exec", "user": "system:node:worker-3",
         "signature": "cobaltstrike-beacon"},
        {"provider": "k8s-audit", "verb": "delete", "object": "networkpolicies", "user": "dev-user-42"},
        {"provider": "k8s-audit", "verb": "get", "object": "secrets", "user": "svc-account-anon",
         "cve": "cve-2024-3400"},
    ],
    "endpoint": [
        {"provider": "syslog", "process": "mimikatz.exe", "host": "WIN-ENDPOINT-14", "user": "jdoe"},
        {"provider": "syslog", "process": "powershell.exe", "host": "WIN-ENDPOINT-02",
         "cmdline": "-enc JAB..."},
        {"provider": "syslog", "process": "sshd", "host": "lnx-bastion-01", "event": "auth_failure_burst"},
    ],
}

_RESOURCE_POOL = {
    "cloud": ["i-0a1b2c3d4e5f60789", "sg-0912af33cc1", "arn:aws:iam::123456789012:role/lambda-exec"],
    "application": ["pod/payments-api-7f9c8d-x2k4v", "deployment/checkout-svc", "namespace/prod-core"],
    "endpoint": ["WIN-ENDPOINT-14", "WIN-ENDPOINT-02", "lnx-bastion-01"],
}


def _build_alert() -> InfrastructureAlert:
    source = random.choice(_SOURCES)
    template = random.choice(_TEMPLATES[source]).copy()
    resource_id = random.choice(_RESOURCE_POOL[source])
    severity = random.randint(1, 10)
    return InfrastructureAlert(
        timestamp=datetime.now(timezone.utc),
        source=source,
        severity=severity,
        ioc_payload=template,
        resource_id=resource_id,
    )


async def telemetry_generator(
    queue: asyncio.Queue[InfrastructureAlert | dict],
    stop_event: asyncio.Event,
    min_interval: float = 0.4,
    max_interval: float = 1.5,
) -> None:
    """Continuously pushes multi-source telemetry (and occasional malformed
    payloads) into the shared queue until stop_event is set."""
    while not stop_event.is_set():
        await asyncio.sleep(random.uniform(min_interval, max_interval))

        # Simulate occasional malformed telemetry to exercise error handling
        # without ever blocking the pipeline.
        if random.random() < 0.08:
            malformed = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source": "unknown-source",  # invalid literal -> ValidationError
                "severity": 99,  # out of range -> ValidationError
                "ioc_payload": {},
                "resource_id": "",
            }
            await queue.put(malformed)
            log.info("[DETECTOR] Malformed telemetry ingested (will be quarantined)")
            continue

        alert = _build_alert()
        await queue.put(alert)
        log.info(
            "[DETECTOR] Alert Ingested id=%s source=%s severity=%d resource=%s",
            alert.alert_id[:8], alert.source, alert.severity, alert.resource_id,
        )

    log.info("[DETECTOR] Telemetry generator stopped")


# --------------------------------------------------------------------------- #
# 3 & 4. Micro-Agents
# --------------------------------------------------------------------------- #

TRIAGE_TOOLS: list[dict] = [
    {
        "name": "lookup_threat_intel",
        "description": (
            "Query the threat-intelligence database for a specific indicator "
            "(IP address, file hash, process name, domain, CVE ID, etc.) drawn "
            "from the alert's raw telemetry payload. Returns whether the "
            "indicator is a known IoC. Call this once per distinct indicator "
            "worth verifying before rendering your final verdict."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "indicator": {
                    "type": "string",
                    "description": "The raw indicator value to check, e.g. an IP, hash, process name, or CVE ID.",
                }
            },
            "required": ["indicator"],
            "additionalProperties": False,
        },
    },
    {
        "name": "report_triage_verdict",
        "description": (
            "Record your final triage verdict for this alert. Call this exactly "
            "once, after you have gathered enough threat-intelligence context to "
            "make a confident determination."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "active_threat": {
                    "type": "boolean",
                    "description": "True if this alert represents an active, credible threat requiring containment.",
                },
                "confidence": {
                    "type": "number",
                    "description": "Confidence in this verdict, from 0.0 (no confidence) to 1.0 (certain).",
                },
                "matched_iocs": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Indicators confirmed as known IoCs via lookup_threat_intel.",
                },
                "reasoning": {
                    "type": "string",
                    "description": "A concise 1-3 sentence explanation of the verdict for the incident record.",
                },
            },
            "required": ["active_threat", "confidence", "matched_iocs", "reasoning"],
            "additionalProperties": False,
        },
    },
]

# Isolation/remediation tool names double as the pydantic Literal action_type
# values on IsolationAction/RemediationAction -- Claude's tool choice IS the
# typed action, no separate mapping step needed.
ISOLATION_TOOLS: list[dict] = [
    {
        "name": "security_group_lockdown",
        "description": (
            "Apply a deny-all containment posture to a cloud resource by revoking "
            "security-group ingress/egress. Use for cloud-source alerts involving "
            "compute instances, IAM roles, or networking constructs."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "detail": {
                    "type": "string",
                    "description": "Concise description of the specific lockdown action taken and why it was chosen.",
                }
            },
            "required": ["detail"],
            "additionalProperties": False,
        },
    },
    {
        "name": "container_termination",
        "description": (
            "Terminate or evict a Kubernetes pod/container immediately. Use for "
            "application-source alerts involving a compromised workload."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "detail": {
                    "type": "string",
                    "description": "Concise description of the specific termination action taken and why it was chosen.",
                }
            },
            "required": ["detail"],
            "additionalProperties": False,
        },
    },
    {
        "name": "gateway_ip_block",
        "description": (
            "Block a host or IP at the network/API-gateway perimeter. Use for "
            "endpoint-source alerts or alerts requiring perimeter network isolation."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "detail": {
                    "type": "string",
                    "description": "Concise description of the specific block rule applied and why it was chosen.",
                }
            },
            "required": ["detail"],
            "additionalProperties": False,
        },
    },
]

REMEDIATION_TOOLS: list[dict] = [
    {
        "name": "container_restart",
        "description": "Restart a container/pod from a clean image with policy re-applied. Use to restore application workloads.",
        "input_schema": {
            "type": "object",
            "properties": {
                "detail": {
                    "type": "string",
                    "description": "Concise description of the restart action taken and why it was chosen.",
                }
            },
            "required": ["detail"],
            "additionalProperties": False,
        },
    },
    {
        "name": "patch_deployment",
        "description": "Deploy a signature/OS patch bundle to a host. Use to remediate endpoint-source compromises.",
        "input_schema": {
            "type": "object",
            "properties": {
                "detail": {
                    "type": "string",
                    "description": "Concise description of the patch action taken and why it was chosen.",
                }
            },
            "required": ["detail"],
            "additionalProperties": False,
        },
    },
    {
        "name": "image_rollback",
        "description": "Roll a cloud resource back to its last known-good image/snapshot. Use to remediate cloud-source compromises.",
        "input_schema": {
            "type": "object",
            "properties": {
                "detail": {
                    "type": "string",
                    "description": "Concise description of the rollback action taken and why it was chosen.",
                }
            },
            "required": ["detail"],
            "additionalProperties": False,
        },
    },
]


class TriageAgent:
    """Cross-references IoCs and renders an active-threat verdict via a Claude
    tool-use loop: the model queries threat intel, then calls
    `report_triage_verdict` exactly once. Falls back to a severity-threshold
    heuristic if the model is unavailable or fails to produce a verdict."""

    SEVERITY_THREAT_THRESHOLD = 6
    MAX_TOOL_ITERATIONS = 4

    def __init__(self, client: anthropic.AsyncAnthropic) -> None:
        self._client = client

    def _lookup_threat_intel(self, indicator: str) -> str:
        """Mock threat-intel backend the model queries via tool use."""
        normalized = indicator.strip().lower()
        for ioc in KNOWN_IOCS:
            if normalized and (normalized in ioc.lower() or ioc.lower() in normalized):
                return f"MATCH: '{indicator}' corresponds to known IoC '{ioc}' in the threat intelligence database."
        return f"NO MATCH: '{indicator}' is not present in the threat intelligence database."

    def _fallback(self, alert: InfrastructureAlert, reason: str) -> TriageResult:
        active_threat = alert.severity >= self.SEVERITY_THREAT_THRESHOLD
        log.warning(
            "[TRIAGE] id=%s LLM triage unavailable (%s) — using fallback heuristic",
            alert.alert_id[:8], reason,
        )
        return TriageResult(
            alert=alert,
            active_threat=active_threat,
            matched_iocs=[],
            confidence=0.3,
            reasoning=f"FALLBACK (rule-based, LLM unavailable: {reason}) — severity-threshold heuristic applied.",
        )

    async def evaluate(self, alert: InfrastructureAlert) -> TriageResult:
        messages: list[dict] = [
            {
                "role": "user",
                "content": (
                    "Analyze the following security alert and determine whether it "
                    "represents an active threat.\n\n"
                    f"Alert ID: {alert.alert_id}\n"
                    f"Source: {alert.source}\n"
                    f"Severity (1-10, reported by source system): {alert.severity}\n"
                    f"Resource: {alert.resource_id}\n"
                    f"Timestamp: {alert.timestamp.isoformat()}\n"
                    f"Raw telemetry payload: {json.dumps(alert.ioc_payload)}\n\n"
                    "Use the lookup_threat_intel tool to check any indicators in the "
                    "payload (IPs, hashes, process names, CVEs, etc.) against threat "
                    "intelligence before rendering your verdict. Then call "
                    "report_triage_verdict exactly once with your final determination."
                ),
            }
        ]

        try:
            for _ in range(self.MAX_TOOL_ITERATIONS):
                response = await self._client.messages.create(
                    model=MODEL,
                    max_tokens=2048,
                    thinking={"type": "adaptive"},
                    output_config={"effort": "high"},
                    tools=TRIAGE_TOOLS,
                    messages=messages,
                )

                if response.stop_reason == "refusal":
                    return self._fallback(alert, "model refused analysis")

                tool_use_blocks = [b for b in response.content if b.type == "tool_use"]
                if not tool_use_blocks:
                    break  # model stopped without ever calling report_triage_verdict

                messages.append({"role": "assistant", "content": response.content})
                tool_results: list[dict] = []
                verdict_input: dict | None = None

                for block in tool_use_blocks:
                    if block.name == "lookup_threat_intel":
                        indicator = str(block.input.get("indicator", ""))
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": self._lookup_threat_intel(indicator),
                        })
                    elif block.name == "report_triage_verdict":
                        verdict_input = block.input
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": "Verdict recorded.",
                        })

                messages.append({"role": "user", "content": tool_results})

                if verdict_input is not None:
                    result = TriageResult(
                        alert=alert,
                        active_threat=bool(verdict_input["active_threat"]),
                        matched_iocs=[str(x) for x in verdict_input.get("matched_iocs", [])],
                        confidence=float(verdict_input["confidence"]),
                        reasoning=str(verdict_input["reasoning"]),
                    )
                    log.info(
                        "[TRIAGE] id=%s active_threat=%s confidence=%.2f matched_iocs=%s reasoning=%s",
                        alert.alert_id[:8], result.active_threat, result.confidence,
                        result.matched_iocs or "none", result.reasoning,
                    )
                    return result

            return self._fallback(alert, "exhausted tool-use iterations without a verdict")

        except anthropic.APIError as exc:
            return self._fallback(alert, f"{type(exc).__name__}: {exc}")
        except Exception as exc:  # noqa: BLE001 - never let a malformed model response kill the pipeline
            return self._fallback(alert, f"unexpected error: {exc}")


class IsolationAgent:
    """Claude selects and justifies the containment action via a forced tool
    choice over the isolation playbook. Falls back to a deterministic,
    source-based playbook if the model is unavailable."""

    def __init__(self, client: anthropic.AsyncAnthropic) -> None:
        self._client = client

    def _fallback(self, triage: TriageResult, reason: str) -> IsolationAction:
        alert = triage.alert
        if alert.source == "cloud":
            action_type: Literal["security_group_lockdown", "container_termination", "gateway_ip_block"] = (
                "security_group_lockdown"
            )
            detail = f"FALLBACK (rule-based, LLM unavailable: {reason}) — revoked ingress/egress on {alert.resource_id}."
        elif alert.source == "application":
            action_type = "container_termination"
            detail = f"FALLBACK (rule-based, LLM unavailable: {reason}) — terminated {alert.resource_id}."
        else:  # endpoint
            action_type = "gateway_ip_block"
            detail = f"FALLBACK (rule-based, LLM unavailable: {reason}) — blocked {alert.resource_id} at the perimeter."

        log.warning(
            "[ISOLATION] id=%s LLM isolation unavailable (%s) — using fallback playbook",
            alert.alert_id[:8], reason,
        )
        return IsolationAction(
            resource_id=alert.resource_id,
            action_type=action_type,
            detail=detail,
            executed_at=datetime.now(timezone.utc),
        )

    async def contain(self, triage: TriageResult) -> IsolationAction:
        alert = triage.alert
        prompt = (
            "A security alert has been confirmed as an active threat and requires "
            "immediate containment.\n\n"
            f"Alert source: {alert.source}\n"
            f"Resource: {alert.resource_id}\n"
            f"Severity: {alert.severity}\n"
            f"Triage reasoning: {triage.reasoning}\n"
            f"Matched IoCs: {triage.matched_iocs or 'none'}\n"
            f"Raw telemetry: {json.dumps(alert.ioc_payload)}\n\n"
            "Choose exactly one containment action from the available tools and "
            "execute it to isolate this resource."
        )

        try:
            response = await self._client.messages.create(
                model=MODEL,
                max_tokens=1024,
                output_config={"effort": "medium"},
                tools=ISOLATION_TOOLS,
                tool_choice={"type": "any"},
                messages=[{"role": "user", "content": prompt}],
            )

            if response.stop_reason == "refusal":
                return self._fallback(triage, "model refused to select an action")

            tool_use = next((b for b in response.content if b.type == "tool_use"), None)
            if tool_use is None:
                return self._fallback(triage, "model did not select a containment action")

            action = IsolationAction(
                resource_id=alert.resource_id,
                action_type=tool_use.name,  # type: ignore[arg-type]  # tool names ARE the Literal values
                detail=str(tool_use.input.get("detail", "")),
                executed_at=datetime.now(timezone.utc),
            )
            log.info(
                "[ISOLATION] id=%s Resource %s isolated via %s -> %s",
                alert.alert_id[:8], action.resource_id, action.action_type, action.detail,
            )
            return action

        except anthropic.APIError as exc:
            return self._fallback(triage, f"{type(exc).__name__}: {exc}")
        except Exception as exc:  # noqa: BLE001
            return self._fallback(triage, f"unexpected error: {exc}")


class RemediationAgent:
    """Claude selects and justifies the recovery action via a forced tool
    choice over the remediation playbook. Falls back to a deterministic,
    source-based playbook if the model is unavailable."""

    def __init__(self, client: anthropic.AsyncAnthropic) -> None:
        self._client = client

    def _fallback(self, triage: TriageResult, isolation: IsolationAction, reason: str) -> RemediationAction:
        alert = triage.alert
        if alert.source == "cloud":
            action_type: Literal["container_restart", "patch_deployment", "image_rollback"] = "image_rollback"
            detail = f"FALLBACK (rule-based, LLM unavailable: {reason}) — rolled back {alert.resource_id} to last known-good snapshot."
        elif alert.source == "application":
            action_type = "container_restart"
            detail = f"FALLBACK (rule-based, LLM unavailable: {reason}) — restarted {alert.resource_id} from a clean image."
        else:  # endpoint
            action_type = "patch_deployment"
            detail = f"FALLBACK (rule-based, LLM unavailable: {reason}) — deployed patch bundle to {alert.resource_id}."

        log.warning(
            "[REMEDIATION] id=%s LLM remediation unavailable (%s) — using fallback playbook",
            alert.alert_id[:8], reason,
        )
        return RemediationAction(
            resource_id=alert.resource_id,
            action_type=action_type,
            detail=detail,
            executed_at=datetime.now(timezone.utc),
        )

    async def recover(self, isolation: IsolationAction, triage: TriageResult) -> RemediationAction:
        alert = triage.alert
        prompt = (
            "A compromised resource has just been contained and now needs recovery.\n\n"
            f"Alert source: {alert.source}\n"
            f"Resource: {alert.resource_id}\n"
            f"Severity: {alert.severity}\n"
            f"Triage reasoning: {triage.reasoning}\n"
            f"Containment action taken: {isolation.action_type} -> {isolation.detail}\n\n"
            "Choose exactly one recovery action from the available tools and execute "
            "it to restore this resource to a healthy state."
        )

        try:
            response = await self._client.messages.create(
                model=MODEL,
                max_tokens=1024,
                output_config={"effort": "medium"},
                tools=REMEDIATION_TOOLS,
                tool_choice={"type": "any"},
                messages=[{"role": "user", "content": prompt}],
            )

            if response.stop_reason == "refusal":
                return self._fallback(triage, isolation, "model refused to select an action")

            tool_use = next((b for b in response.content if b.type == "tool_use"), None)
            if tool_use is None:
                return self._fallback(triage, isolation, "model did not select a recovery action")

            action = RemediationAction(
                resource_id=alert.resource_id,
                action_type=tool_use.name,  # type: ignore[arg-type]  # tool names ARE the Literal values
                detail=str(tool_use.input.get("detail", "")),
                executed_at=datetime.now(timezone.utc),
            )
            log.info(
                "[REMEDIATION] id=%s Infrastructure restored: %s -> %s",
                alert.alert_id[:8], action.resource_id, action.detail,
            )
            return action

        except anthropic.APIError as exc:
            return self._fallback(triage, isolation, f"{type(exc).__name__}: {exc}")
        except Exception as exc:  # noqa: BLE001
            return self._fallback(triage, isolation, f"unexpected error: {exc}")


# --------------------------------------------------------------------------- #
# 5. Orchestrator
# --------------------------------------------------------------------------- #

class IncidentResponseOrchestrator:
    """Centralized, thread-safe async orchestrator that consumes alerts from
    the queue and routes them through the Triage -> Isolation -> Remediation
    pipeline, concurrently and isolated per-alert."""

    def __init__(
        self,
        queue: asyncio.Queue[InfrastructureAlert | dict],
        *,
        client: anthropic.AsyncAnthropic,
        max_concurrent_pipelines: int = 8,
    ) -> None:
        self._queue = queue
        self._triage_agent = TriageAgent(client)
        self._isolation_agent = IsolationAgent(client)
        self._remediation_agent = RemediationAgent(client)
        self._semaphore = asyncio.Semaphore(max_concurrent_pipelines)

        # Thread/task-safe counters guarded by an internal lock.
        self._lock = asyncio.Lock()
        self._stats = {
            "ingested": 0,
            "quarantined": 0,
            "triaged": 0,
            "contained": 0,
            "remediated": 0,
        }

    async def _bump(self, key: str) -> None:
        async with self._lock:
            self._stats[key] += 1

    async def stats_snapshot(self) -> dict[str, int]:
        async with self._lock:
            return dict(self._stats)

    async def _quarantine_malformed(self, raw: dict) -> None:
        """Error handling for malformed logs — never blocks the pipeline."""
        try:
            InfrastructureAlert.model_validate(raw)
        except ValidationError as exc:
            await self._bump("quarantined")
            log.warning(
                "[DETECTOR] Quarantined malformed alert: %s",
                "; ".join(f"{e['loc']}: {e['msg']}" for e in exc.errors()),
            )

    async def _run_pipeline(self, alert: InfrastructureAlert) -> None:
        """Isolated, per-alert async pipeline execution."""
        async with self._semaphore:
            try:
                await self._bump("ingested")

                triage = await self._triage_agent.evaluate(alert)
                await self._bump("triaged")

                if not triage.active_threat:
                    log.info(
                        "[PIPELINE] id=%s below threat threshold -> no action taken",
                        alert.alert_id[:8],
                    )
                    return

                isolation = await self._isolation_agent.contain(triage)
                await self._bump("contained")

                remediation = await self._remediation_agent.recover(isolation, triage)
                await self._bump("remediated")

                log.info(
                    "[PIPELINE] id=%s complete: severity=%d isolation=%s remediation=%s",
                    alert.alert_id[:8], alert.severity,
                    isolation.action_type, remediation.action_type,
                )
            except Exception:  # noqa: BLE001 - pipeline must never crash the orchestrator
                log.exception("[PIPELINE] Unhandled error processing alert id=%s", alert.alert_id[:8])

    async def run(self, ingestion_done: asyncio.Event) -> None:
        """Main consumption loop: pulls from the queue and dispatches
        concurrent, isolated pipeline tasks until ingestion has fully
        completed (producer finished, including its last enqueue) and the
        queue is drained. Gating on `ingestion_done` rather than a shared
        "stop requested" flag avoids a race where the consumer could observe
        a momentarily-empty queue and exit before the producer's final
        in-flight `put` lands."""
        pending: set[asyncio.Task[None]] = set()

        while not (ingestion_done.is_set() and self._queue.empty()):
            try:
                item = await asyncio.wait_for(self._queue.get(), timeout=0.5)
            except asyncio.TimeoutError:
                continue

            if isinstance(item, InfrastructureAlert):
                task = asyncio.create_task(self._run_pipeline(item))
            else:
                task = asyncio.create_task(self._quarantine_malformed(item))

            pending.add(task)
            task.add_done_callback(pending.discard)
            self._queue.task_done()

        if pending:
            await asyncio.gather(*pending, return_exceptions=True)


# --------------------------------------------------------------------------- #
# CLI entry point
# --------------------------------------------------------------------------- #

async def main(run_seconds: float = 15.0) -> None:
    try:
        client = anthropic.AsyncAnthropic()  # resolves ANTHROPIC_API_KEY / ant auth profile
    except anthropic.AnthropicError as exc:
        log.error("Failed to initialize Anthropic client: %s", exc)
        log.error("Set ANTHROPIC_API_KEY, or run `ant auth login`, before starting the engine.")
        return

    queue: asyncio.Queue[InfrastructureAlert | dict] = asyncio.Queue(maxsize=256)
    stop_event = asyncio.Event()
    ingestion_done = asyncio.Event()

    async with client:
        orchestrator = IncidentResponseOrchestrator(queue, client=client)

        log.info(
            "=== Automated Incident Response Engine starting (model=%s, window=%.0fs) ===",
            MODEL, run_seconds,
        )

        producer = asyncio.create_task(telemetry_generator(queue, stop_event))
        consumer = asyncio.create_task(orchestrator.run(ingestion_done))

        try:
            await asyncio.sleep(run_seconds)
        finally:
            stop_event.set()
            await producer  # producer fully drained, including any final in-flight put
            ingestion_done.set()
            await consumer

        stats = await orchestrator.stats_snapshot()
        log.info(
            "=== Engine stopped. ingested=%d quarantined=%d triaged=%d contained=%d remediated=%d ===",
            stats["ingested"], stats["quarantined"], stats["triaged"], stats["contained"], stats["remediated"],
        )


if __name__ == "__main__":
    duration = float(sys.argv[1]) if len(sys.argv) > 1 else 15.0
    try:
        asyncio.run(main(duration))
    except KeyboardInterrupt:
        log.info("Interrupted by user — shutting down.")
