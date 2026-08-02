"""Tests for SHAP-style feature attribution (M4).

The demo kill chain is caught by the hybrid hard-signal layer (its ML raw
score sits inside the learned baseline), so these tests exercise attribution
with a genuinely ML-anomalous vector where the isolation forest itself
deviates.
"""

from __future__ import annotations

from backend.detection.isolation_forest import IsolationForestDetector
from backend.features.extractor import FeatureExtractor, ProcessFeatures
from backend.features.names import FEATURE_NAMES


def _vectors(events):
    return FeatureExtractor().extract(events)


def _anomalous_vector(normal_events) -> ProcessFeatures:
    base = _vectors(normal_events)[0]
    values = {name: float(base.values[name]) for name in FEATURE_NAMES}
    values.update(
        {
            "tmp_execs": 5.0,
            "suspicious_ports": 4.0,
            "privilege_escalations": 3.0,
            "script_interpreters": 4.0,
            "chain_length": 20.0,
        }
    )
    return ProcessFeatures(
        pid=1,
        exe="/usr/bin/python3",
        chain_key="synthetic",
        window_start=0.0,
        window_end=1.0,
        values=values,
    )


def test_anomalous_vector_is_ml_flagged(normal_events):
    detector = IsolationForestDetector().fit(_vectors(normal_events))
    result = detector.predict(_anomalous_vector(normal_events))
    assert result.flagged
    assert result.anomaly_score == 1.0


def test_contributions_deterministic(normal_events):
    detector = IsolationForestDetector().fit(_vectors(normal_events))
    vector = _anomalous_vector(normal_events)
    assert detector.feature_contributions(vector) == detector.feature_contributions(vector)


def test_contributions_positive_and_ordered(normal_events):
    detector = IsolationForestDetector().fit(_vectors(normal_events))
    vector = _anomalous_vector(normal_events)
    contributions = detector.feature_contributions(vector)
    assert all(v >= 0 for v in contributions.values())
    assert contributions["chain_length"] > 0
    top = max(contributions.items(), key=lambda kv: kv[1])
    assert top[0] == "chain_length"


def test_contributions_fallback_without_baseline_rows(normal_events):
    detector = IsolationForestDetector().fit(_vectors(normal_events))
    detector._baseline_rows = None  # simulate a pre-M4 persisted model
    contributions = detector.feature_contributions(_anomalous_vector(normal_events))
    assert all(v >= 0 for v in contributions.values())
    assert max(contributions.values()) > 0


def test_attribution_budget_is_respected(normal_events):
    detector = IsolationForestDetector(background_samples=4).fit(_vectors(normal_events))
    contributions = detector.feature_contributions(_anomalous_vector(normal_events))
    assert max(contributions.values()) > 0


def test_baseline_rows_persisted(normal_events, tmp_path):
    path = str(tmp_path / "detector.joblib")
    detector = IsolationForestDetector().fit(_vectors(normal_events))
    detector.save(path)
    restored = IsolationForestDetector.load(path)
    assert restored._baseline_rows is not None
    assert restored._baseline_rows.shape[1] == len(FEATURE_NAMES)


def test_loaded_detector_attribution_matches(normal_events, tmp_path):
    path = str(tmp_path / "detector.joblib")
    vector = _anomalous_vector(normal_events)
    detector = IsolationForestDetector().fit(_vectors(normal_events))
    detector.save(path)
    restored = IsolationForestDetector.load(path)
    assert detector.feature_contributions(vector) == restored.feature_contributions(vector)


def test_attack_chain_attribution_is_honest_zero(normal_events, attack_events):
    """The demo attack is caught by hard signals; ML attribution stays ~0."""
    detector = IsolationForestDetector().fit(_vectors(normal_events))
    vector = _vectors(attack_events)[0]
    contributions = detector.feature_contributions(vector)
    assert all(v >= 0 for v in contributions.values())
    assert max(contributions.values()) < 0.05
