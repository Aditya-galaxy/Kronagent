"""
Integration tests for the measured evaluation harness.
"""

from __future__ import annotations

import pytest
import subprocess
import sys


def test_run_eval_script_execution() -> None:
    """Verifies that run_eval.py runs successfully in mock mode."""
    # Execute run_eval.py as a subprocess to verify CLI interface and execution
    result = subprocess.run(
        [sys.executable, "run_eval.py"],
        capture_output=True,
        text=True,
        check=True
    )
    
    assert result.returncode == 0
    assert "KRONAGENT PIPELINE EVALUATION REPORT" in result.stdout
    assert "EVALUATION PASSED" in result.stdout
    assert "F1 Score:  100.00%" in result.stdout
