#!/usr/bin/env bash
#
# Aegis — live terminal demo.
#
# A narrated, five-act walkthrough of the platform. Everything on screen is the
# REAL system driving its REAL CLIs (run_slice.py / promote.py / approve.py) —
# no mocks, no canned output. It runs entirely in dry-run (nothing touches any
# cloud or cluster), so it's safe to run anywhere, live, in front of anyone.
#
# Usage:
#   ./demo.sh              # interactive — press Enter between acts (for presenting)
#   AEGIS_DEMO_AUTO=1 ./demo.sh   # hands-off — auto-advances (for recording)
#
# Optional: AEGIS_PY=/path/to/python3 to force a specific interpreter.

set -euo pipefail
cd "$(dirname "$0")"

# --- styling -------------------------------------------------------------- #
if [ -t 1 ]; then
  BOLD=$'\033[1m'; DIM=$'\033[2m'; RESET=$'\033[0m'
  CYAN=$'\033[36m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'; BLUE=$'\033[34m'
else
  BOLD=""; DIM=""; RESET=""; CYAN=""; GREEN=""; YELLOW=""; RED=""; BLUE=""
fi

# --- locate a Python with the project deps -------------------------------- #
PY="${AEGIS_PY:-}"
if [ -z "$PY" ]; then
  for cand in /usr/local/bin/python3 python3 /opt/homebrew/bin/python3; do
    if command -v "$cand" >/dev/null 2>&1 && "$cand" -c 'import pydantic, google.genai, dotenv' >/dev/null 2>&1; then
      PY="$cand"; break
    fi
  done
fi
if [ -z "$PY" ]; then
  echo "${RED}Could not find a Python 3 with the project dependencies installed.${RESET}"
  echo "Install with:  python3 -m pip install pydantic google-genai python-dotenv boto3"
  echo "Or set AEGIS_PY=/path/to/python3"
  exit 1
fi

# --- helpers -------------------------------------------------------------- #
banner() {
  printf "\n${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════════════╗${RESET}\n"
  printf   "${BOLD}${CYAN}║${RESET}  ${BOLD}%-66s${RESET}${BOLD}${CYAN}║${RESET}\n" "$1"
  printf   "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════════════════╝${RESET}\n"
}
say()  { printf "${DIM}   %s${RESET}\n" "$1"; }
run()  { printf "\n${YELLOW}   \$ %s${RESET}\n\n" "$*"; "$@"; }
pause() {
  if [ "${AEGIS_DEMO_AUTO:-0}" = "1" ]; then sleep "${1:-3}"
  else printf "\n${DIM}   ── press Enter to continue ──${RESET}"; read -r _ || true; fi
}

# Pull one pending approval id for a given action class from the store.
pending_id() {
  "$PY" - "$1" <<'PYEOF'
import json, sys
ac = sys.argv[1]
try:
    d = json.load(open("aegis_approvals.json"))
except FileNotFoundError:
    sys.exit(0)
for k, v in d.items():
    if v["action_class"] == ac and v["status"] == "pending":
        print(k); break
PYEOF
}

# Force dry-run for the whole demo, regardless of the caller's environment.
export AEGIS_DRY_RUN=true
export AEGIS_KILL_SWITCH=false

# Fresh state so the demo is reproducible.
rm -f aegis_audit.jsonl aegis_approvals.json aegis_allowlist.json

# ========================================================================== #
clear || true
printf "${BOLD}${BLUE}"
cat <<'ART'
     ▄▄▄       ▓█████   ▄████  ██▓  ██████
    ▒████▄     ▓█   ▀  ██▒ ▀█▒▓██▒▒██    ▒
    ▒██  ▀█▄   ▒███   ▒██░▄▄▄░▒██▒░ ▓██▄
    ░██▄▄▄▄██  ▒▓█  ▄ ░▓█  ██▓░██░  ▒   ██▒
     ▓█   ▓██▒ ░▒████▒░▒▓███▀▒░██░▒██████▒▒
ART
printf "${RESET}"
printf "   ${BOLD}Autonomous AI Threat Defense — with guardrails enterprises can trust${RESET}\n"
printf "   ${DIM}Everything below is the real system, running in dry-run. Nothing is mocked.${RESET}\n"
printf "   ${DIM}Interpreter: %s${RESET}\n" "$PY"
pause 2

# -------------------------------------------------------------------------- #
banner "ACT 1 — Safe by default (the earn-trust posture)"
say "On a cold start, the auto-execute allowlist is EMPTY. That means the"
say "platform is structurally incapable of touching production unattended —"
say "every containment action must be approved by a human until a class of"
say "action has explicitly earned trust. This is the opposite of the"
say "'fully autonomous, no human in the loop' pitch most competitors sell."
run "$PY" promote.py list
pause 2

# -------------------------------------------------------------------------- #
banner "ACT 2 — Detection + graduated autonomy (AWS + Kubernetes)"
say "Live findings arrive from two totally different substrates: AWS GuardDuty"
say "(IAM/EC2) and Kubernetes audit events (pods/nodes/deployments). Each flows"
say "through the SAME pipeline: triage (deterministic + LLM) -> a deterministic"
say "policy engine that gates every action by reversibility and blast radius."
say ""
say "Watch what the policy engine does: reversible, single-resource actions are"
say "AUTO-eligible; destructive ones (terminate instance, delete pod, scale to"
say "zero) are structurally routed to APPROVAL — no allowlist entry can override"
say "that ceiling."
run "$PY" run_slice.py
pause 3

# -------------------------------------------------------------------------- #
banner "ACT 3 — Earning trust (audited governance, no restart)"
say "An operator decides 'disable_access_key' has proven safe — it's reversible,"
say "affects exactly one credential, and it's been reliable. They promote it."
say "Every promotion is written to the tamper-evident audit log: who, when, why."
run "$PY" promote.py add disable_access_key --by alice --reason "30 days incident-free; reversible, single-credential blast radius"
say ""
say "Now the SAME finding is re-processed. disable_access_key AUTO-executes"
say "(still dry-run) — while the destructive actions stay gated. The change took"
say "effect immediately, with no restart."
run "$PY" run_slice.py aws samples/guardduty_findings.json
pause 3

# -------------------------------------------------------------------------- #
banner "ACT 4 — Human-in-the-loop approval (before the side effect)"
say "The destructive and not-yet-trusted actions are waiting for a human. This is"
say "real approval — it happens BEFORE the action runs, not a retrospective log."
APR_ID="$(pending_id isolate_instance_sg)"
if [ -z "$APR_ID" ]; then APR_ID="$(pending_id attach_deny_all_to_principal)"; fi
run "$PY" approve.py list
if [ -n "$APR_ID" ]; then
  say ""
  say "The analyst reviews the plan + rollback, then authorizes it with attribution:"
  run "$PY" approve.py approve "$APR_ID" --by alice --reason "confirmed compromise; isolate for forensics"
else
  say "(no gated action available to approve in this run)"
fi
pause 3

# -------------------------------------------------------------------------- #
banner "ACT 5 — Tamper-evident audit (the compliance backbone)"
say "Every decision and action — triage, policy, containment, approvals,"
say "governance — is one hash-chained record. This is what EU AI Act Article 12"
say "(automatic logging) and Article 14 (human oversight) require, and it's what"
say "makes autonomous response defensible instead of a black box."
run "$PY" -c "from aegis.audit import AuditLog; ok,b=AuditLog.verify('aegis_audit.jsonl'); print('  chain verification:', 'OK — intact' if ok else f'BROKEN at line {b}')"
say ""
say "Now watch what happens if an attacker (or an insider) edits a past record to"
say "cover their tracks — we tamper with one line of a COPY of the log:"
"$PY" - <<'PYEOF'
import json
lines = open("aegis_audit.jsonl").read().splitlines()
i = min(2, len(lines) - 1)
env = json.loads(lines[i])
env["record"].setdefault("payload", {})["note"] = "ATTACKER EDITED THIS RECORD"
lines[i] = json.dumps(env)
open("aegis_audit_tampered.jsonl", "w").write("\n".join(lines) + "\n")
print(f"     (edited record on line {i+1} of the copy — the content, not the hash)")
PYEOF
run "$PY" -c "from aegis.audit import AuditLog; ok,b=AuditLog.verify('aegis_audit_tampered.jsonl'); print('  verification of tampered copy:', 'OK' if ok else f'>>> TAMPERING DETECTED at line {b} <<<')"
rm -f aegis_audit_tampered.jsonl
pause 2

# -------------------------------------------------------------------------- #
banner "Recap — what makes this different"
printf "   ${GREEN}✓${RESET} Detects across substrates (AWS + Kubernetes) through one engine\n"
printf "   ${GREEN}✓${RESET} EXECUTES containment — most 'AI SOC' tools stop at investigation\n"
printf "   ${GREEN}✓${RESET} Graduated autonomy: reversible auto-acts, destructive needs a human\n"
printf "   ${GREEN}✓${RESET} Earn-trust governance — promote one action class at a time, audited\n"
printf "   ${GREEN}✓${RESET} Tamper-evident audit trail — compliance-ready (EU AI Act Art. 12/14)\n"
printf "\n   ${DIM}Everything shown ran in dry-run. The same paths execute for real against a\n"
printf "   live account once an action class is promoted and AEGIS_DRY_RUN=false.${RESET}\n\n"
