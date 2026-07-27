#!/usr/bin/env bash
#
# Kronagent — live terminal demo.
#
# A narrated, five-act walkthrough of the platform. Everything on screen is the
# REAL system driving its REAL CLIs (run_slice.py / promote.py / approve.py) —
# no mocks, no canned output. It runs entirely in dry-run (nothing touches any
# cloud or cluster), so it's safe to run anywhere, live, in front of anyone.
#
# Usage:
#   ./demo.sh              # interactive — press Enter between acts (for presenting)
#   KRONAGENT_DEMO_AUTO=1 ./demo.sh   # hands-off — auto-advances (for recording)
#
# Optional: KRONAGENT_PY=/path/to/python3 to force a specific interpreter.

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
PY="${KRONAGENT_PY:-}"
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
  echo "Or set KRONAGENT_PY=/path/to/python3"
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
  if [ "${KRONAGENT_DEMO_AUTO:-0}" = "1" ]; then sleep "${1:-3}"
  else printf "\n${DIM}   ── press Enter to continue ──${RESET}"; read -r _ || true; fi
}

# Is the local SQS testbed (moto server) available?
have_testbed() { "$PY" -c 'import moto.server, boto3' >/dev/null 2>&1; }

# Pull one pending approval id for a given action class from the store.
pending_id() {
  "$PY" - "$1" <<'PYEOF'
import json, sys
ac = sys.argv[1]
try:
    d = json.load(open("kronagent_approvals.json"))
except FileNotFoundError:
    sys.exit(0)
for k, v in d.items():
    if v["action_class"] == ac and v["status"] == "pending":
        print(k); break
PYEOF
}

# Force dry-run for the whole demo, regardless of the caller's environment.
export KRONAGENT_DRY_RUN=true
export KRONAGENT_KILL_SWITCH=false

# Fresh state so the demo is reproducible.
rm -f kronagent_audit.jsonl kronagent_approvals.json kronagent_allowlist.json

# ========================================================================== #
clear || true
printf "${BOLD}${BLUE}"
cat <<'ART'
   ██  ██ █████  ██████ ██  ██ ██████ ██████ ██████ ██  ██ ██████
   ██ ██  ██  ██ ██  ██ ███ ██ ██  ██ ██     ██     ███ ██   ██
   ████   █████  ██  ██ ██████ ██████ ██ ███ █████  ██████   ██
   ██ ██  ██ ██  ██  ██ ██ ███ ██  ██ ██  ██ ██     ██ ███   ██
   ██  ██ ██  ██ ██████ ██  ██ ██  ██ ██████ ██████ ██  ██   ██
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
banner "ACT 2 — Multi-cloud detection + graduated autonomy (AWS + K8s + GCP)"
say "Live findings arrive from multi-cloud substrates: AWS GuardDuty (IAM/EC2),"
say "Kubernetes audit events (pods/nodes), and GCP Security Command Center (IAM/VMs)."
say "Each flows through the SAME pipeline: triage (deterministic + LLM) -> threat intel"
say "(MITRE ATT&CK + STIX feeds) -> a deterministic policy engine that gates actions."
say ""
say "Watch what the policy engine does: reversible, single-resource actions are"
say "AUTO-eligible; destructive ones (terminate instance, delete pod, scale to"
say "zero) are structurally routed to APPROVAL — no allowlist entry can override"
say "that ceiling."
run "$PY" run_slice.py
pause 3

# -------------------------------------------------------------------------- #
banner "ACT 2.5 — Live async ingestion (real SQS stream, no cloud account)"
if have_testbed; then
  say "Acts so far replayed findings from disk. Real deployments ingest a LIVE,"
  say "asynchronous stream: GuardDuty -> EventBridge -> SQS, long-polled by the"
  say "platform. We prove that exact path here with a local SQS emulator (moto)"
  say "— no AWS account, no Docker. (We chose moto over LocalStack, which went"
  say "proprietary + auth-gated in March 2026. See testbed/README.md.)"
  say ""
  say "A background emulator streams EventBridge-wrapped findings into a real SQS"
  say "queue; the platform long-polls and drives each one through the full pipeline."
  export AWS_ACCESS_KEY_ID=testing AWS_SECRET_ACCESS_KEY=testing AWS_SESSION_TOKEN=testing
  TB_PORT=5057
  mkdir -p ./.demo_tmp
  "$PY" testbed/sqs_emulator.py serve --port "$TB_PORT" > ./.demo_tmp/kronagent_demo_testbed.log 2>&1 &
  TB_PID=$!
  # Wait for the queue URL to appear.
  TB_QURL=""
  for _ in $(seq 1 30); do
    TB_QURL="$( (grep -m1 'Queue URL' ./.demo_tmp/kronagent_demo_testbed.log 2>/dev/null || true) | awk '{print $NF}')"
    [ -n "$TB_QURL" ] && break; sleep 0.3
  done
  if [ -n "$TB_QURL" ]; then
    printf "\n${YELLOW}   \$ KRONAGENT_SQS_ENDPOINT_URL=http://localhost:%s KRONAGENT_SQS_QUEUE_URL=… run_slice.py${RESET}\n\n" "$TB_PORT"
    # run_slice long-polls until interrupted; run it for a bounded window, then
    # stop it the same way Ctrl-C would (it drains gracefully).
    KRONAGENT_SQS_ENDPOINT_URL="http://localhost:$TB_PORT" KRONAGENT_SQS_QUEUE_URL="$TB_QURL" \
      KRONAGENT_SQS_WAIT_SECONDS=2 \
      KRONAGENT_AUDIT_PATH=./.demo_tmp/kronagent_demo_live.jsonl \
      KRONAGENT_APPROVAL_PATH=./.demo_tmp/kronagent_demo_live_appr.json \
      KRONAGENT_ALLOWLIST_PATH=./.demo_tmp/kronagent_demo_live_allow.json \
      "$PY" run_slice.py &
    LIVE_PID=$!
    sleep 12
    set +e
    kill -INT "$LIVE_PID" 2>/dev/null
    for _ in $(seq 1 12); do kill -0 "$LIVE_PID" 2>/dev/null || break; sleep 0.5; done
    kill -9 "$LIVE_PID" 2>/dev/null
    wait "$LIVE_PID" 2>/dev/null
    set -e
  else
    say "(emulator did not start in time; skipping the live act)"
  fi
  set +e
  kill "$TB_PID" 2>/dev/null
  wait "$TB_PID" 2>/dev/null
  set -e
  rm -rf ./.demo_tmp
else
  say "Live-ingestion act skipped — the local SQS testbed isn't installed."
  say "Enable it with:  python3 -m pip install -r testbed/requirements.txt"
  say "Then re-run the demo to see the real GuardDuty -> EventBridge -> SQS path."
fi
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
banner "ACT 5 — Tamper-evident audit & OCSF SIEM export"
say "Every decision and action — triage, policy, containment, approvals,"
say "governance — is one hash-chained record. This is what EU AI Act Article 12"
say "(automatic logging) and Article 14 (human oversight) require, and it's what"
say "makes autonomous response defensible instead of a black box."
run "$PY" -c "from kronagent.audit import AuditLog; ok,b=AuditLog.verify('kronagent_audit.jsonl'); print('  chain verification:', 'OK — intact' if ok else f'BROKEN at line {b}')"
say ""
say "Now watch what happens if an attacker (or an insider) edits a past record to"
say "cover their tracks — we tamper with one line of a COPY of the log:"
"$PY" - <<'PYEOF'
import json
lines = open("kronagent_audit.jsonl").read().splitlines()
i = min(2, len(lines) - 1)
env = json.loads(lines[i])
env["record"].setdefault("payload", {})["note"] = "ATTACKER EDITED THIS RECORD"
lines[i] = json.dumps(env)
open("kronagent_audit_tampered.jsonl", "w").write("\n".join(lines) + "\n")
print(f"     (edited record on line {i+1} of the copy — the content, not the hash)")
PYEOF
run "$PY" -c "from kronagent.audit import AuditLog; ok,b=AuditLog.verify('kronagent_audit_tampered.jsonl'); print('  verification of tampered copy:', 'OK' if ok else f'>>> TAMPERING DETECTED at line {b} <<<')"
rm -f kronagent_audit_tampered.jsonl
say ""
say "Audit logs are normalized and exported to OCSF format for Splunk/Sentinel SIEM integration:"
run "$PY" run_siem_export.py
rm -f kronagent_ocsf_export.jsonl
pause 2

# -------------------------------------------------------------------------- #
banner "Recap — what makes this different"
printf "   ${GREEN}✓${RESET} Multi-cloud detection (AWS + Kubernetes + GCP SCC) through one engine\n"
printf "   ${GREEN}✓${RESET} Advisory Threat Intel (MITRE ATT&CK mapping + STIX/TAXII feed matching)\n"
printf "   ${GREEN}✓${RESET} EXECUTES containment — most 'AI SOC' tools stop at investigation\n"
printf "   ${GREEN}✓${RESET} Graduated autonomy: reversible auto-acts, destructive needs a human\n"
printf "   ${GREEN}✓${RESET} Earn-trust governance — promote one action class at a time, audited\n"
printf "   ${GREEN}✓${RESET} Tamper-evident audit trail & OCSF SIEM export (EU AI Act Art. 12/14)\n"
printf "\n   ${DIM}Everything shown ran in dry-run. The same paths execute for real against a\n"
printf "   live account once an action class is promoted and KRONAGENT_DRY_RUN=false.${RESET}\n\n"

