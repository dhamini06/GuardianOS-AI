"""Tests for the explainability layer."""

from __future__ import annotations

from backend.detection.isolation_forest import IsolationForestDetector
from backend.explainability.explainer import RuleBasedExplainer
from backend.explainability.mitre import map_techniques
from backend.features.extractor import FeatureExtractor


def _explain(normal_events, attack_events):
    detector = IsolationForestDetector().fit(FeatureExtractor().extract(normal_events))
    vector = FeatureExtractor().extract(attack_events)[0]
    result = detector.predict(vector)
    return RuleBasedExplainer().explain(vector, result)


def test_explanation_produces_reasons(normal_events, attack_events):
    explanation = _explain(normal_events, attack_events)
    assert explanation.reasons
    assert any("tmp" in r for r in explanation.reasons)
    assert any("privilege" in r for r in explanation.reasons)


def test_explanation_narrative_is_reverse_shell(normal_events, attack_events):
    explanation = _explain(normal_events, attack_events)
    assert "REVERSE SHELL" in explanation.summary


def test_explanation_chain_is_ordered(normal_events, attack_events):
    explanation = _explain(normal_events, attack_events)
    positions = [step.position for step in explanation.chain]
    assert positions == sorted(positions)
    assert len(explanation.chain) >= 5


def test_mitre_mapping_covers_kill_chain(normal_events, attack_events):
    attack = [e for e in attack_events]
    techniques = map_techniques(attack)
    ids = {t.technique_id for t in techniques}
    assert "T1105" in ids          # ingress tool transfer
    assert "T1204.002" in ids      # malicious file execution
    assert "T1059.004" in ids      # unix shell


def test_mitre_mapping_empty():
    assert map_techniques([]) == []


def test_mitre_normal_activity_no_false_positives(normal_events):
    """Normal pip/browser usage must not map to ingress/exec techniques."""
    techniques = map_techniques(normal_events[:12])
    ids = {t.technique_id for t in techniques}
    assert "T1105" not in ids
    assert "T1204.002" not in ids
