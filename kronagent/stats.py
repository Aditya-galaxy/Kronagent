"""
Small statistics shared by the evaluation harness and the shadow-mode report.

Both publish rates computed from small samples, and a rate from ten findings
read as a point estimate implies far more certainty than ten findings contain.
Every rate either surface reports travels with an interval, and the interval is
computed here once so the two cannot disagree about what "95%" means.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import math
from statistics import NormalDist


def wilson_score_interval(successes: int, total: int,
                          confidence: float = 0.95) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion.

    Chosen over the normal approximation because it behaves at the edges that
    small corpora live at: 10/10 yields an interval reaching well below 100%
    instead of the degenerate [1.0, 1.0].

    This previously lived in run_eval.py, where it accepted `confidence` and
    then hard-coded z = 1.96 — so asking for a 99% interval silently returned a
    95% one. z is derived from `confidence` now.
    """
    if total <= 0:
        return 0.0, 0.0
    if not 0.0 < confidence < 1.0:
        raise ValueError(f"confidence must be strictly between 0 and 1, got {confidence}")
    if not 0 <= successes <= total:
        raise ValueError(f"successes must be within [0, {total}], got {successes}")

    z = NormalDist().inv_cdf(1 - (1 - confidence) / 2)
    p = successes / total
    denominator = 1 + z ** 2 / total
    centre = p + z ** 2 / (2 * total)
    margin = z * math.sqrt((p * (1 - p) + z ** 2 / (4 * total)) / total)
    return max(0.0, (centre - margin) / denominator), min(1.0, (centre + margin) / denominator)


def binomial_upper_bound(failures: int, total: int, confidence: float = 0.95) -> float:
    """One-sided exact (Clopper-Pearson) upper bound on a failure rate.

    The largest true rate under which seeing this few failures in `total`
    trials would still happen with probability at least 1 - confidence. "With
    95% confidence the rate is below this."

    Exact rather than Wilson because the case that matters is zero failures in
    a modest sample, and a promotion decision should not lean on an
    approximation there. With no failures it is 1 - (1 - confidence)^(1/total):
    about 3/total at 95%, the "rule of three". With no trials it is 1.0:
    nothing has been shown.
    """
    if not 0.0 < confidence < 1.0:
        raise ValueError(f"confidence must be strictly between 0 and 1, got {confidence}")
    if total <= 0:
        return 1.0
    if not 0 <= failures <= total:
        raise ValueError(f"failures must be within [0, {total}], got {failures}")
    if failures == total:
        return 1.0
    alpha = 1.0 - confidence
    if failures == 0:
        return 1.0 - alpha ** (1.0 / total)

    def at_most(p: float) -> float:
        """P(X <= failures) for X ~ Binomial(total, p), summed in log space."""
        logs = [math.lgamma(total + 1) - math.lgamma(k + 1) - math.lgamma(total - k + 1)
                + k * math.log(p) + (total - k) * math.log1p(-p) for k in range(failures + 1)]
        peak = max(logs)
        return math.exp(peak) * sum(math.exp(v - peak) for v in logs)

    low, high = failures / total, 1.0 - 1e-12
    for _ in range(80):                       # P(X <= k) falls as p rises: bisect for alpha
        mid = (low + high) / 2
        if at_most(mid) > alpha:
            low = mid
        else:
            high = mid
    return high


def clean_trials_needed(max_rate: float, confidence: float = 0.95) -> int:
    """How many trials with no failure it takes to show a rate below `max_rate`."""
    if not 0.0 < max_rate < 1.0:
        raise ValueError(f"max_rate must be strictly between 0 and 1, got {max_rate}")
    return math.ceil(math.log(1.0 - confidence) / math.log1p(-max_rate))
