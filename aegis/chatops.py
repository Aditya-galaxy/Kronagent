"""
ChatOps Integration Utility for Aegis.

Handles Slack Block Kit formatting, sending webhook or bot notifications,
updating interactive message cards, and verifying Slack signature headers.
"""

from __future__ import annotations

import hmac
import hashlib
import json
import urllib.request
from typing import Any, Optional
from urllib.error import URLError

from .config import Settings
from .approvals import ApprovalRequest


def verify_slack_signature(
    signing_secret: str,
    request_body: bytes,
    timestamp: str,
    signature: str
) -> bool:
    """
    Verify the HMAC-SHA256 signature of incoming Slack interactive payloads
    to prevent spoofing.
    """
    if not signing_secret or not signature or not timestamp:
        return False
    try:
        # Slack protocol: v0:timestamp:body
        sig_basestring = b"v0:" + timestamp.encode("utf-8") + b":" + request_body
        computed = "v0=" + hmac.new(
            signing_secret.encode("utf-8"),
            sig_basestring,
            hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(computed, signature)
    except Exception:
        return False


class ChatOpsNotifier:
    @staticmethod
    def _get_severity_emoji(sev: float) -> str:
        if sev >= 9.0:
            return "🔴 CRITICAL"
        if sev >= 7.0:
            return "🟠 HIGH"
        if sev >= 4.0:
            return "🟡 MEDIUM"
        return "🔵 LOW"

    @classmethod
    def build_slack_blocks(cls, req: ApprovalRequest, status_text: Optional[str] = None) -> list[dict[str, Any]]:
        """
        Build Slack Block Kit layout for the approval request.
        If status_text is provided, replace interactive buttons with the decision verdict.
        """
        emoji = cls._get_severity_emoji(req.severity)
        
        blocks = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"🛡️ *Aegis Incident Containment Approval Request* [ID: `{req.request_id}`]"
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Severity:* {emoji} ({req.severity})"},
                    {"type": "mrkdwn", "text": f"*Action Class:* `{req.action_class.value}`"},
                    {"type": "mrkdwn", "text": f"*Finding ID:* `{req.finding_id}`"},
                    {"type": "mrkdwn", "text": f"*Target:* `{req.target}`"}
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Rationale:* _{req.rationale}_\n*Policy Gate Reason:* {req.policy_reason}"
                }
            }
        ]

        # Add planned operations list
        if req.planned_api_calls:
            api_calls = "\n".join(f"• `{c}`" for c in req.planned_api_calls)
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Planned Operations:*\n{api_calls}"
                }
            })

        # Add buttons or decision verdict status
        if status_text:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"👉 *Verdict:* {status_text}"
                }
            })
        else:
            blocks.append({
                "type": "actions",
                "block_id": f"actions_{req.request_id}",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Approve ✅"},
                        "style": "primary",
                        "value": req.request_id,
                        "action_id": "approve_action"
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Reject / Deny ❌"},
                        "style": "danger",
                        "value": req.request_id,
                        "action_id": "deny_action"
                    }
                ]
            })

        return blocks

    @classmethod
    def send_approval_notification(cls, settings: Settings, req: ApprovalRequest) -> Optional[str]:
        """
        Send the interactive Slack message. Returns the message timestamp (ts) if successful.
        """
        if not settings.slack_bot_token or not settings.slack_channel_id:
            return None

        url = "https://slack.com/api/chat.postMessage"
        payload = {
            "channel": settings.slack_channel_id,
            "text": f"Aegis Approval Request for {req.action_class.value} on {req.target}",
            "blocks": cls.build_slack_blocks(req)
        }

        req_bytes = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "Authorization": f"Bearer {settings.slack_bot_token}"
        }

        try:
            http_req = urllib.request.Request(url, data=req_bytes, headers=headers, method="POST")
            with urllib.request.urlopen(http_req, timeout=10) as response:
                res_body = json.loads(response.read().decode("utf-8"))
                if res_body.get("ok"):
                    return res_body.get("ts")
                else:
                    print(f"[-] Slack API error: {res_body.get('error')}")
        except Exception as e:
            print(f"[-] Failed to send Slack notification: {e}")
        return None

    @classmethod
    def update_approval_notification(
        cls,
        settings: Settings,
        ts: str,
        req: ApprovalRequest,
        status_text: str
    ) -> bool:
        """
        Update the existing Slack approval card to remove interactive buttons.
        """
        if not settings.slack_bot_token or not settings.slack_channel_id or not ts:
            return False

        url = "https://slack.com/api/chat.update"
        payload = {
            "channel": settings.slack_channel_id,
            "ts": ts,
            "text": f"Aegis Approval Update for {req.action_class.value} on {req.target}",
            "blocks": cls.build_slack_blocks(req, status_text)
        }

        req_bytes = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "Authorization": f"Bearer {settings.slack_bot_token}"
        }

        try:
            http_req = urllib.request.Request(url, data=req_bytes, headers=headers, method="POST")
            with urllib.request.urlopen(http_req, timeout=10) as response:
                res_body = json.loads(response.read().decode("utf-8"))
                return bool(res_body.get("ok"))
        except Exception as e:
            print(f"[-] Failed to update Slack notification: {e}")
        return False
