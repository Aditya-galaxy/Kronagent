"""
Telemetry sanitization and shielding against adversarial prompt injection.
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
    r"(?i)override\s+policy",
    r"(?i)you\s+are\s+now",
    r"(?i)system\s+prompt",
    r"(?i)bypass\s+security",
    r"(?i)mark\s+as\s+safe",
    r"(?i)false\s+alarm",
    r"(?i)set\s+severity\s+to\s+0",
]


def sanitize_text(text: str, max_length: int = 500) -> str:
    """Truncates text and neutralizes prompt-injection payloads."""
    if not text:
        return ""

    # 1. Truncate context to avoid long context attacks / resource exhaustion
    text = text[:max_length]

    # 2. Strip potential prompt formatting separators (markdown fence, rules)
    text = text.replace("```", "'''")
    text = text.replace("---", "___")
    text = text.replace("===", "___")

    # 3. Neutralize injection keywords by replacing with redaction tag
    for kw_pattern in _INJECTION_KEYWORDS:
        text = re.sub(kw_pattern, "[REDACTED_INJECTION_PAYLOAD]", text)

    return text


def sanitize_ip(ip_str: Optional[str]) -> Optional[str]:
    """Ensures the remote IP is a valid IPv4/IPv6 address, rejecting injection text."""
    if not ip_str:
        return None

    ip_str = ip_str.strip()
    try:
        # Validate using standard ipaddress parser
        ipaddress.ip_address(ip_str)
        return ip_str
    except ValueError:
        # If it fails validation, it contains unexpected characters or injection attempts. Reject it.
        return None


def sanitize_resource_ref(ref: ResourceRef) -> ResourceRef:
    """Sanitizes resource identifiers and attributes to permit only safe characters."""
    # Permitted chars: alphanumeric, dots, dashes, slashes, colons, underscores
    safe_pattern = re.compile(r"[^a-zA-Z0-9\.\-\/\:\_]")

    clean_id = safe_pattern.sub("", ref.id)
    clean_kind = safe_pattern.sub("", ref.kind)

    # Clean attributes dictionary
    clean_attrs = {}
    for k, v in ref.attributes.items():
        clean_key = safe_pattern.sub("", k)
        if isinstance(v, str):
            clean_value = sanitize_text(v, max_length=100)
        else:
            clean_value = v
        clean_attrs[clean_key] = clean_value

    return ResourceRef(
        kind=clean_kind,
        id=clean_id,
        attributes=clean_attrs,
    )


def sanitize_finding(finding: Finding) -> Finding:
    """Clones a finding, applying strict sanitization layers across all fields."""
    sanitized_resources = [sanitize_resource_ref(r) for r in finding.resources]

    return finding.model_copy(update={
        "title": sanitize_text(finding.title, max_length=200),
        "description": sanitize_text(finding.description, max_length=1000),
        "finding_type": sanitize_text(finding.finding_type, max_length=100),
        "remote_ip": sanitize_ip(finding.remote_ip),
        "resources": sanitized_resources,
    })
