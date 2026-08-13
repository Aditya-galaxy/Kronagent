"""
Telemetry sanitization: prompt-injection shielding, secret redaction, and
reversible identifier masking for LLM-facing copies of a finding.

Three distinct jobs, deliberately kept apart because they have different
correctness requirements:

  1. **Injection neutralisation** (free text). Detector-supplied titles and
     descriptions are attacker-influenceable, so override phrasing is replaced
     and prompt separators are defanged. Lossy on purpose.

  2. **Secret redaction** (irreversible). An access key or private key that
     appears in telemetry must never reach a model *and* must never come back.
     There is no placeholder for these — the value is destroyed.

  3. **Identifier masking** (reversible). Resource ids, hostnames and IPs are
     replaced with stable placeholders like `<SERVICE_ACCOUNT_0>`, and the
     mapping is kept in a MaskingContext held by the caller. The model reasons
     over placeholders; the platform keeps the real values.

The third one replaces what this module used to do, and the difference matters.
The previous implementation stripped disallowed characters from identifiers:

    exfil-sa@proj.iam.gserviceaccount.com  ->  exfil-saproj.iam.gserviceaccount.com

That is both a privacy failure and a correctness one. The identifier still went
to the model nearly intact, so little was protected; and it was *corrupted*, so
campaign memory stored an identity that no longer matched the real resource and
two findings about the same service account failed to correlate. Character
filtering forced a choice between "safe to send" and "usable as an identity"
and lost both. A placeholder gives up neither: nothing recognisable leaves the
process, and the original is recoverable exactly.

Containment is unaffected by any of this. Action targets are read from the
original Finding, never from a masked copy — see providers.plan_actions. Masking
exists so a model can be shown an incident without being handed the estate.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import ipaddress
import re
from typing import Optional

from .model import Finding, ResourceRef

# Regex for common jailbreak/override keywords to strip or neutralize
_INJECTION_KEYWORDS = [
    r"(?i)ignore\s+(?:all\s+|previous\s+)?instructions",
    r"(?i)ignore\s+(?:all\s+)?guardrails",
    r"(?i)override\s+policy",
    r"(?i)system\s+override",
    r"(?i)you\s+are\s+now",
    r"(?i)system\s+prompt",
    r"(?i)bypass\s+security",
    r"(?i)mark\s+as\s+safe",
    r"(?i)false\s+alarm",
    r"(?i)set\s+severity\s+to\s+0",
    r"<\|im_start\|>",
    r"<\|im_end\|>",
    r"\[INST\]",
    r"\[/INST\]",
]


# Credentials that may appear in telemetry. These are redacted irreversibly:
# unlike a resource id, there is no downstream use for the real value, so
# keeping a recoverable copy would be a liability with no benefit.
_SECRET_PATTERNS = [
    (re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "[REDACTED_AWS_KEY_ID]"),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "[REDACTED_GCP_API_KEY]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "[REDACTED_SLACK_TOKEN]"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY]"),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+"),
     "[REDACTED_JWT]"),
]

# Resource kinds arrive provider-prefixed (`gcp.service_account`,
# `aws.ec2.instance`). The last segment is the useful part of a placeholder.
_NON_ALNUM = re.compile(r"[^a-zA-Z0-9]+")


def _placeholder_label(kind: str) -> str:
    tail = kind.rsplit(".", 1)[-1] if kind else "resource"
    label = _NON_ALNUM.sub("_", tail).strip("_").upper()
    return label or "RESOURCE"


class MaskingContext:
    """Placeholder <-> original mapping for one investigation.

    Two properties make this useful rather than merely private:

      * **Stable within a context.** The same value always yields the same
        placeholder, so a model can see that `<SERVICE_ACCOUNT_0>` appears in
        both the current finding and a prior one. Correlation depends on this;
        random per-occurrence tokens would destroy exactly the signal the
        correlation agent exists to find.

      * **Scoped to one investigation.** The map is not global state. Two
        concurrent investigations do not share placeholders, so a value cannot
        leak between tenants through a shared numbering scheme.
    """

    __slots__ = ("_counters", "_to_original", "_to_placeholder")

    def __init__(self) -> None:
        self._to_placeholder: dict[str, str] = {}
        self._to_original: dict[str, str] = {}
        self._counters: dict[str, int] = {}

    def placeholder_for(self, value: str, kind: str = "resource") -> str:
        """Register a value and return its stable placeholder."""
        if not value:
            return value
        existing = self._to_placeholder.get(value)
        if existing is not None:
            return existing

        label = _placeholder_label(kind)
        index = self._counters.get(label, 0)
        self._counters[label] = index + 1
        placeholder = f"<{label}_{index}>"

        self._to_placeholder[value] = placeholder
        self._to_original[placeholder] = value
        return placeholder

    def mask_text(self, text: str) -> str:
        """Replace any already-registered value appearing in free text.

        Longest first: an account id can contain a shorter registered value as
        a substring, and replacing the short one first would corrupt the long
        one into a half-masked string that maps back to nothing.
        """
        if not text:
            return text
        for original in sorted(self._to_placeholder, key=len, reverse=True):
            text = text.replace(original, self._to_placeholder[original])
        return text

    def unmask(self, text: str) -> str:
        """Restore real values in model output, for the human reading it.

        Without this an operator reads "`<SERVICE_ACCOUNT_0>` exfiltrated data"
        in the incident record and has to go and look up which account that was
        — during an incident, which is the worst possible moment.
        """
        if not text:
            return text
        for placeholder, original in self._to_original.items():
            text = text.replace(placeholder, original)
        return text

    def mapping(self) -> dict[str, str]:
        """placeholder -> original, as a copy.

        For tests and for a debug view. Never audit this: an audit log is
        exportable, and this map is the thing masking exists to keep in-process.
        """
        return dict(self._to_original)

    def __len__(self) -> int:
        return len(self._to_original)


def redact_secrets(text: str) -> str:
    """Destroy credential-shaped substrings. Not reversible, by design."""
    if not text:
        return ""
    for pattern, replacement in _SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def sanitize_text(text: str, max_length: int = 500) -> str:
    """Truncate free text and neutralize prompt-injection payloads."""
    if not text:
        return ""

    text = redact_secrets(text)

    # Truncate to bound context-stuffing and resource exhaustion.
    text = text[:max_length]

    # Defang prompt separators so injected content cannot open a new "section".
    text = text.replace("```", "'''")
    text = text.replace("---", "___")
    text = text.replace("===", "___")

    for kw_pattern in _INJECTION_KEYWORDS:
        text = re.sub(kw_pattern, "[REDACTED_INJECTION_PAYLOAD]", text)

    return text


def sanitize_ip(ip_str: Optional[str]) -> Optional[str]:
    """Ensure the remote IP parses as an address, rejecting injection text."""
    if not ip_str:
        return None
    ip_str = ip_str.strip()
    try:
        ipaddress.ip_address(ip_str)
        return ip_str
    except ValueError:
        return None


def mask_resource_ref(ref: ResourceRef, ctx: MaskingContext) -> ResourceRef:
    """Replace a resource's identity with a placeholder, preserving its shape.

    `kind` is deliberately NOT masked. It carries no tenant information —
    "gcp.service_account" is true of every GCP estate — and the model needs it
    to reason about what kind of thing was touched.

    Attribute *values* are masked too, because an attribute named `hostname` is
    exactly as identifying as an id.
    """
    masked_attrs: dict = {}
    for k, v in ref.attributes.items():
        clean_key = _NON_ALNUM.sub("_", str(k)).strip("_")
        if isinstance(v, str) and v:
            masked_attrs[clean_key] = ctx.placeholder_for(v, f"{ref.kind}.{clean_key}")
        else:
            masked_attrs[clean_key] = v

    return ResourceRef(
        kind=ref.kind,
        id=ctx.placeholder_for(ref.id, ref.kind),
        attributes=masked_attrs,
    )


def mask_finding(finding: Finding,
                 ctx: Optional[MaskingContext] = None) -> tuple[Finding, MaskingContext]:
    """An LLM-safe copy of a finding, plus the context needed to reverse it.

    Pass an existing context to mask several findings consistently — that is
    what lets the correlation agent see one placeholder spanning a current
    finding and its history.

    The returned Finding is for prompts only. Containment reads the original.
    """
    ctx = ctx if ctx is not None else MaskingContext()

    masked_resources = [mask_resource_ref(r, ctx) for r in finding.resources]

    # Validate the IP first, so injection text is dropped rather than masked
    # into a placeholder that would imply it had been a real address. Then mask
    # it: a remote IP identifies infrastructure exactly as a hostname does, and
    # correlation needs to recognise the same attacker across findings.
    ip = sanitize_ip(finding.remote_ip)
    masked_ip = ctx.placeholder_for(ip, "remote_ip") if ip else None

    return finding.model_copy(update={
        "title": ctx.mask_text(sanitize_text(finding.title, max_length=200)),
        "description": ctx.mask_text(sanitize_text(finding.description, max_length=1000)),
        "finding_type": sanitize_text(finding.finding_type, max_length=100),
        "remote_ip": masked_ip,
        "resources": masked_resources,
    }), ctx


def sanitize_finding(finding: Finding) -> Finding:
    """Backwards-compatible single-finding masking.

    Kept for callers that build a prompt, read the model's structured output and
    never need to reverse anything. Anything that shows model text to a human,
    or that masks more than one finding, should use mask_finding and hold the
    context — otherwise the operator reads placeholders.
    """
    return mask_finding(finding)[0]


def sanitize_telemetry(finding: Finding, ctx: Optional[MaskingContext] = None) -> tuple[Finding, MaskingContext]:
    """Unified entry point for full telemetry sanitization.

    Performs secret redaction, prompt-injection neutralizing, and placeholder
    resource masking on an incoming finding.
    """
    return mask_finding(finding, ctx)

