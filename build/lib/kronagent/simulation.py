"""
Drift simulation engine to continuously test and validate the health of the Kronagent pipeline.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import logging

import json
import os

from .model import Finding


_log = logging.getLogger("kronagent.simulation")

class DriftSimulationEngine:
    """Generates synthetic benign threat alerts and validates the audit log trail

    to ensure the end-to-end pipeline is fully functional and healthy.
    """

    def generate_finding(self, finding_id: str) -> Finding:
        """Constructs a synthetic benign finding designed to trace the pipeline."""
        return Finding(
            provider="aws",
            finding_id=finding_id,
            finding_type="Kronagent:Simulation/DriftCheck",
            severity=3.0,
            raw={"is_simulation": True},
        )

    def verify_pipeline_health(self, audit_log_path: str, finding_id: str) -> bool:
        """Parses the audit log to assert that the synthetic finding successfully

        traversed ingestion and triage stages.
        """
        if not os.path.exists(audit_log_path):
            return False

        stages = set()
        with open(audit_log_path, "r") as fh:
            for line in fh:
                if not line.strip():
                    continue
                try:
                    envelope = json.loads(line.strip())
                    record = envelope.get("record", {})
                    if record.get("finding_id") == finding_id:
                        stages.add(record.get("stage"))
                except json.JSONDecodeError:
                    # A malformed line in the audit log is itself worth
                    # knowing about — the log is hash-chained, so corruption
                    # here is a signal, not noise.
                    _log.warning("skipping malformed audit line in %s", audit_log_path)
                    continue

        # A functional pipeline must at least complete the triage stage audit record
        return "triage" in stages
