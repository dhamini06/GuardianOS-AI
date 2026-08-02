"""Rule-based explainer: assembles evidence into an Explanation."""

from __future__ import annotations

from backend.core.analysis import DetectionResult, Explanation
from backend.explainability.attribution import (
    narrative_for,
    reasons_from_contributions,
)
from backend.explainability.chain import build_chain
from backend.explainability.mitre import map_techniques
from backend.features.extractor import ProcessFeatures


class RuleBasedExplainer:
    """MVP explainer combining feature attribution, chain and MITRE mapping."""

    def explain(self, vector: ProcessFeatures, result: DetectionResult) -> Explanation:
        reasons, strong_count = reasons_from_contributions(
            vector, result.contributing_features
        )
        chain = build_chain(vector.related_events)
        techniques = map_techniques(vector.related_events)
        summary = narrative_for(vector, reasons, strong_count, techniques)

        if not reasons:
            reasons.append(
                "Score is elevated relative to the machine's learned baseline, "
                "but no single feature dominates; combined behaviour is unusual."
            )

        return Explanation(
            summary=summary,
            reasons=reasons,
            chain=chain,
            mitre=techniques,
            confidence=result.confidence,
            severity=result.severity,
        )
