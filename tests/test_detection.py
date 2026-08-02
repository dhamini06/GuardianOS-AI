"""Tests for the AI detection layer."""

from __future__ import annotations

import pytest
from joblib import dump, load

from backend.detection.base import DetectorError
from backend.detection.isolation_forest import IsolationForestDetector
from backend.features.extractor import FeatureExtractor
from backend.features.names import FEATURE_NAMES, FEATURE_SCHEMA_VERSION


def _vectors(events):
    return FeatureExtractor().extract(events)


def test_predict_before_fit_raises(normal_events):
    detector = IsolationForestDetector()
    with pytest.raises(DetectorError):
        detector.predict(_vectors(normal_events)[0])


def test_fit_requires_data():
    detector = IsolationForestDetector()
    with pytest.raises(DetectorError):
        detector.fit([])


def test_attack_is_flagged(normal_events, attack_events):
    detector = IsolationForestDetector().fit(_vectors(normal_events))
    result = detector.predict(_vectors(attack_events)[0])
    assert result.flagged
    assert result.anomaly_score >= 0.6
    assert result.confidence == pytest.approx(result.anomaly_score)


def test_normal_activity_is_not_flagged(normal_events):
    detector = IsolationForestDetector().fit(_vectors(normal_events))
    for vector in _vectors(normal_events):
        result = detector.predict(vector)
        assert not result.flagged, f"normal chain {vector.chain_key} flagged"


def test_contributions_summarise_deviation(normal_events, attack_events):
    detector = IsolationForestDetector().fit(_vectors(normal_events))
    contributions = detector.feature_contributions(_vectors(attack_events)[0])
    assert "tmp_execs" in contributions
    assert "suspicious_ports" in contributions
    assert max(contributions.values()) >= 0


def test_save_and_load_roundtrip(normal_events, attack_events, tmp_path):
    path = str(tmp_path / "detector.joblib")
    detector = IsolationForestDetector().fit(_vectors(normal_events))
    detector.save(path)
    restored = IsolationForestDetector.load(path)
    a = detector.predict(_vectors(attack_events)[0])
    b = restored.predict(_vectors(attack_events)[0])
    assert a.anomaly_score == b.anomaly_score


def test_save_persists_schema_version(normal_events, tmp_path):
    path = str(tmp_path / "detector.joblib")
    IsolationForestDetector().fit(_vectors(normal_events)).save(path)
    assert load(path)["schema_version"] == FEATURE_SCHEMA_VERSION


def test_load_rejects_unknown_schema(normal_events, tmp_path):
    path = str(tmp_path / "detector.joblib")
    IsolationForestDetector().fit(_vectors(normal_events)).save(path)
    payload = load(path)
    payload["schema_version"] = 999
    dump(payload, path)
    with pytest.raises(DetectorError, match="schema"):
        IsolationForestDetector.load(path)


def test_feature_schema_is_canonical():
    assert FEATURE_NAMES
    assert len(FEATURE_NAMES) == len(set(FEATURE_NAMES))
