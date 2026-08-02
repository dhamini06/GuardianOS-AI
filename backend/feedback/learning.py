"""Feedback-driven reweighting of the online baseline.

Confirmed analyst verdicts steer what the unsupervised baseline treats as
"normal". ``malicious`` chains are excluded from the training set so the
detector never learns an attack as normal; ``benign`` chains are simply
retained (and, when they were previously flagged, added back) so the model
converges on the analyst's definition of normality.
"""

from __future__ import annotations

from backend.features.extractor import ProcessFeatures
from backend.feedback.ledger import FeedbackLedger


def reweight_baseline(
    vectors: list[ProcessFeatures],
    ledger: FeedbackLedger,
) -> list[ProcessFeatures]:
    """Return ``vectors`` minus any chain the analyst confirmed as malicious."""
    malicious = ledger.malicious_keys
    if not malicious:
        return list(vectors)
    return [v for v in vectors if v.chain_key not in malicious]
