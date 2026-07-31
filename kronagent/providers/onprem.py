"""
In-house / on-premises provider: self-hosted detector normalization + host,
account and process containment.

Unlike AWS, GCP and Azure, on-premises infrastructure has no single vendor
schema to normalize — detections come from whatever the organization runs
(Wazuh/OSSEC, Falco on bare metal, Suricata or Zeek, a SIEM correlation rule,
or a hand-rolled syslog parser). So this module defines a small, explicit
*ingestion contract* instead of pretending to parse all of them:

    {
      "detector":  "wazuh",                       # free-text, for provenance
      "alert_id":  "onprem-alert-0001",
      "rule":      {"id": "5710", "name": "ssh_bruteforce_success",
                    "severity": "high"},          # or a numeric "severity": 8.5
      "timestamp": "2026-07-28T02:14:03Z",
      "host":      {"hostname": "db-prod-01.corp.internal",
                    "ip": "10.20.30.41", "site": "dc-east"},
      "account":   {"username": "svc-backup", "domain": "CORP"},
      "process":   {"pid": 44122, "executable": "/usr/bin/xmrig"},
      "source_ip": "185.220.101.7"
    }

Every field except `alert_id` is optional; a detector that only knows about a
host still produces a usable finding. Shipping an adapter for a specific tool
is then a thin mapping into this shape, which keeps tool-specific quirks out of
the platform.

Containment differs from cloud in one important way: there is no provider API.
Isolating a physical host means driving a NAC, a switch, a host firewall, or a
configuration-management runner. Kronagent talks to ONE configured control
plane over HTTP rather than opening SSH sessions and running arbitrary remote
commands — a general-purpose remote-execution channel would be a far larger
attack surface than anything it defends against, and it would hand a subverted
agent a shell on every box.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import asyncio
import urllib.parse
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from ..model import Finding, ResourceRef
from ..schemas import ActionClass, ProposedAction

PROVIDER = "onprem"

# Named severities -> the platform's normalized 0-10 scale. An explicit numeric
# severity in the payload always wins over this table.
_SEVERITY_MAP: dict[str, float] = {
    "CRITICAL": 9.5,
    "HIGH": 8.0,
    "MEDIUM": 5.0,
    "LOW": 2.5,
    "INFO": 1.0,
    "INFORMATIONAL": 1.0,
}

# Fallback severities for well-known detection shapes, used when a detector
# sends a rule name but no severity at all.
_RULE_SEVERITY: dict[str, float] = {
    "ssh_bruteforce_success": 8.0,
    "privilege_escalation": 8.5,
    "credential_dumping": 9.0,
    "crypto_mining": 7.5,
    "lateral_movement": 8.0,
    "malware_detected": 8.5,
    "suspicious_process": 6.0,
    "port_scan": 3.0,
}


# --------------------------------------------------------------------------- #
# Ingestion contract (tolerant of extra fields)
# --------------------------------------------------------------------------- #

class OnPremRule(BaseModel):
    model_config = ConfigDict(extra="allow")
    id: Optional[str] = None
    name: Optional[str] = None
    severity: Optional[Any] = None   # "high" | 8.0 — both accepted


class OnPremHost(BaseModel):
    model_config = ConfigDict(extra="allow")
    hostname: Optional[str] = None
    ip: Optional[str] = None
    site: Optional[str] = None


class OnPremAccount(BaseModel):
    model_config = ConfigDict(extra="allow")
    username: Optional[str] = None
    domain: Optional[str] = None


class OnPremProcess(BaseModel):
    model_config = ConfigDict(extra="allow")
    pid: Optional[int] = None
    executable: Optional[str] = None


class OnPremAlert(BaseModel):
    model_config = ConfigDict(extra="allow")
    detector: Optional[str] = None
    alert_id: Optional[str] = None
    rule: OnPremRule = Field(default_factory=OnPremRule)
    timestamp: Optional[str] = None
    description: Optional[str] = None
    host: OnPremHost = Field(default_factory=OnPremHost)
    account: OnPremAccount = Field(default_factory=OnPremAccount)
    process: OnPremProcess = Field(default_factory=OnPremProcess)
    source_ip: Optional[str] = None
    severity: Optional[Any] = None   # top-level override


def _coerce_severity(value: Any) -> Optional[float]:
    """Accept either a number or a named level. Returns None if unusable, so
    the caller can fall through to the next source of truth."""
    if value is None:
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    if isinstance(value, str):
        text = value.strip()
        named = _SEVERITY_MAP.get(text.upper())
        if named is not None:
            return named
        try:
            return float(text)
        except ValueError:
            return None
    return None


# --------------------------------------------------------------------------- #
# Normalization: in-house alert -> provider-neutral Finding
# --------------------------------------------------------------------------- #

def normalize_onprem(payload: dict) -> Finding:
    alert = OnPremAlert.model_validate(payload)

    rule_name = alert.rule.name or "unknown_rule"
    # Severity precedence: explicit top-level, then rule severity, then the
    # rule-name table, then a neutral default.
    severity = (
        _coerce_severity(alert.severity)
        or _coerce_severity(alert.rule.severity)
        or _RULE_SEVERITY.get(rule_name)
        or 5.0
    )

    resources: list[ResourceRef] = []

    if alert.host.hostname:
        resources.append(ResourceRef(
            kind="onprem.host", id=alert.host.hostname,
            attributes={"ip": alert.host.ip or "", "site": alert.host.site or ""},
        ))

    if alert.account.username:
        resources.append(ResourceRef(
            kind="onprem.account", id=alert.account.username,
            attributes={"domain": alert.account.domain or "",
                        "hostname": alert.host.hostname or ""},
        ))

    if alert.process.pid is not None:
        resources.append(ResourceRef(
            kind="onprem.process", id=str(alert.process.pid),
            attributes={"executable": alert.process.executable or "",
                        "hostname": alert.host.hostname or ""},
        ))

    detector = alert.detector or "in-house detector"
    return Finding(
        provider=PROVIDER,
        finding_id=alert.alert_id or "onprem-finding-unknown",
        finding_type=f"onprem:{rule_name}",
        severity=severity,
        title=f"{detector}: {rule_name}",
        description=alert.description or
                    f"{detector} raised '{rule_name}' on {alert.host.hostname or 'an unnamed host'}.",
        resources=resources,
        remote_ip=alert.source_ip,
        raw=payload,
    )


# --------------------------------------------------------------------------- #
# Planning: Finding -> candidate ProposedActions. Targets come from the
# normalized resources, never from model output.
# --------------------------------------------------------------------------- #

def plan_onprem_actions(finding: Finding) -> list[ProposedAction]:
    actions: list[ProposedAction] = []

    for r in finding.resources:
        if r.kind == "onprem.host":
            actions.append(ProposedAction(
                provider=PROVIDER, action_class=ActionClass.ISOLATE_HOST_NETWORK,
                target=r.id,
                parameters={"ip": r.attributes.get("ip", ""), "site": r.attributes.get("site", "")},
                rationale="Move the host to the quarantine VLAN, cutting its network access "
                          "while leaving it powered on for forensics.",
            ))
        elif r.kind == "onprem.account":
            actions.append(ProposedAction(
                provider=PROVIDER, action_class=ActionClass.DISABLE_LOCAL_ACCOUNT,
                target=r.id,
                parameters={"domain": r.attributes.get("domain", ""),
                            "hostname": r.attributes.get("hostname", "")},
                rationale="Disable the compromised account to stop further authentication.",
            ))
        elif r.kind == "onprem.process":
            actions.append(ProposedAction(
                provider=PROVIDER, action_class=ActionClass.KILL_PROCESS,
                target=r.id,
                parameters={"executable": r.attributes.get("executable", ""),
                            "hostname": r.attributes.get("hostname", "")},
                rationale="Terminate the malicious process (irreversible and destroys volatile "
                          "evidence; approval-gated).",
            ))

    if finding.remote_ip:
        actions.append(ProposedAction(
            provider=PROVIDER, action_class=ActionClass.BLOCK_IP,
            target=finding.remote_ip,
            rationale="Block the remote IP at the perimeter firewall.",
        ))

    return actions


# --------------------------------------------------------------------------- #
# Containment adapter.
#
# plan() is pure and needs no control plane, so dry-run works with nothing
# configured. perform() requires an explicitly configured control-plane URL and
# fails loudly rather than silently doing nothing.
# --------------------------------------------------------------------------- #

_ALLOWED_CONTROL_PLANE_SCHEMES = frozenset({"http", "https"})


def _validated_control_plane_url(raw: str) -> str:
    """Accept only an http(s) control-plane URL, and say so at construction.

    urllib honours whatever scheme it is handed. Left unchecked, a control
    plane configured as `file:///etc/shadow` would be opened as a local file
    and its contents treated as a containment response — a config-to-file-read
    primitive inside the component that holds the most privilege. `ftp://` and
    `gopher://` are equally accepted by urllib and equally unintended.

    The value is operator-supplied rather than attacker-supplied, so this is
    defence in depth, not a patched exploit. It is validated here, at
    construction, so a typo fails at startup with a clear message instead of
    during the incident where containment is first attempted.
    """
    url = (raw or "").strip().rstrip("/")
    if not url:
        return ""                      # unset is legal: plan() works, perform() refuses
    scheme = urllib.parse.urlparse(url).scheme.lower()
    if scheme not in _ALLOWED_CONTROL_PLANE_SCHEMES:
        raise ValueError(
            f"KRONAGENT_ONPREM_CONTROL_PLANE_URL must use http or https, got "
            f"{scheme or 'no scheme'!r} in {url!r}"
        )
    return url


class OnPremContainmentAdapter:
    provider = PROVIDER

    def __init__(self, *, control_plane_url: str = "", quarantine_vlan: str = "",
                 request_timeout: float = 15.0) -> None:
        self._url = _validated_control_plane_url(control_plane_url)
        self._vlan = quarantine_vlan
        self._timeout = request_timeout

    def plan(self, action: ProposedAction) -> tuple[list[str], str, str]:
        ac = action.action_class
        t = action.target
        base = self._url or "<KRONAGENT_ONPREM_CONTROL_PLANE_URL unset>"

        if ac == ActionClass.ISOLATE_HOST_NETWORK:
            vlan = self._vlan or "<KRONAGENT_ONPREM_QUARANTINE_VLAN unset>"
            return (
                [
                    f"GET  {base}/hosts/{t}  # capture current VLAN for rollback",
                    f"POST {base}/hosts/{t}/quarantine  {{'vlan': '{vlan}'}}",
                ],
                f"POST {base}/hosts/{t}/restore  {{'vlan': <original VLAN captured at execution>}}",
                f"isolate host {t} into quarantine VLAN {vlan}",
            )
        if ac == ActionClass.DISABLE_LOCAL_ACCOUNT:
            domain = action.parameters.get("domain", "")
            scope = f"{domain}\\{t}" if domain else t
            return (
                [f"POST {base}/accounts/disable  {{'account': '{scope}'}}"],
                f"POST {base}/accounts/enable  {{'account': '{scope}'}}",
                f"disable account {scope}",
            )
        if ac == ActionClass.KILL_PROCESS:
            host = action.parameters.get("hostname", "") or "<unknown host>"
            exe = action.parameters.get("executable", "")
            return (
                [f"POST {base}/hosts/{host}/processes/{t}/kill  {{'executable': '{exe}'}}"],
                "IRREVERSIBLE — the process and its in-memory state are gone",
                f"kill process {t} ({exe or 'unknown binary'}) on {host}",
            )
        if ac == ActionClass.BLOCK_IP:
            return (
                [f"POST {base}/firewall/deny  {{'cidr': '{t}/32', 'direction': 'both'}}"],
                f"POST {base}/firewall/allow  {{'cidr': '{t}/32'}}",
                f"block remote IP {t} at the perimeter firewall",
            )
        return ([f"# no on-prem planner for {ac.value}"], "unknown", f"unhandled action {ac.value}")

    async def perform(self, action: ProposedAction) -> tuple[str, str]:
        if not self._url:
            raise RuntimeError(
                "KRONAGENT_ONPREM_CONTROL_PLANE_URL is not configured — on-premises "
                "containment has no control plane to drive"
            )
        if action.action_class == ActionClass.ISOLATE_HOST_NETWORK and not self._vlan:
            raise RuntimeError("KRONAGENT_ONPREM_QUARANTINE_VLAN is not configured")
        return await asyncio.to_thread(self._perform_sync, action)

    def _perform_sync(self, action: ProposedAction) -> tuple[str, str]:
        import json
        import urllib.error
        import urllib.request

        path, body, rollback, detail = self._request_for(action)
        target = f"{self._url}{path}"
        # Re-checked here as well as at construction: _url is the only part of
        # this request that comes from outside the code, and this is the last
        # point before a privileged network call.
        if urllib.parse.urlparse(target).scheme.lower() not in _ALLOWED_CONTROL_PLANE_SCHEMES:
            raise RuntimeError(f"refusing non-http(s) control-plane URL: {target!r}")
        req = urllib.request.Request(  # noqa: S310 - scheme validated above
            target,
            data=json.dumps(body).encode(),
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # noqa: S310 - scheme validated at construction and immediately above
                if resp.status >= 300:
                    raise RuntimeError(f"control plane returned HTTP {resp.status}")
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"control plane rejected the request: HTTP {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"control plane unreachable: {exc.reason}") from exc
        return (detail, rollback)

    def _request_for(self, action: ProposedAction) -> tuple[str, dict, str, str]:
        ac = action.action_class
        t = action.target
        if ac == ActionClass.ISOLATE_HOST_NETWORK:
            return (f"/hosts/{t}/quarantine", {"vlan": self._vlan},
                    f"POST {self._url}/hosts/{t}/restore",
                    f"host {t} moved to quarantine VLAN {self._vlan}")
        if ac == ActionClass.DISABLE_LOCAL_ACCOUNT:
            domain = action.parameters.get("domain", "")
            scope = f"{domain}\\{t}" if domain else t
            return ("/accounts/disable", {"account": scope},
                    f"POST {self._url}/accounts/enable {{'account': '{scope}'}}",
                    f"account {scope} disabled")
        if ac == ActionClass.KILL_PROCESS:
            host = action.parameters.get("hostname", "")
            return (f"/hosts/{host}/processes/{t}/kill",
                    {"executable": action.parameters.get("executable", "")},
                    "IRREVERSIBLE — the process and its in-memory state are gone",
                    f"process {t} killed on {host}")
        if ac == ActionClass.BLOCK_IP:
            return ("/firewall/deny", {"cidr": f"{t}/32", "direction": "both"},
                    f"POST {self._url}/firewall/allow {{'cidr': '{t}/32'}}",
                    f"remote IP {t} blocked at the perimeter firewall")
        raise NotImplementedError(f"on-premises execution for {ac.value} is not implemented")
