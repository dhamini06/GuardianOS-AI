"""Tests for the behavioural feature engineering layer."""

from __future__ import annotations

from backend.features.extractor import FeatureExtractor
from backend.features.names import FEATURE_NAMES


def test_feature_names_are_stable():
    assert len(FEATURE_NAMES) == 13
    assert "tmp_execs" in FEATURE_NAMES
    assert "suspicious_ports" in FEATURE_NAMES


def test_extract_returns_one_vector_per_chain(normal_events, attack_events):
    extractor = FeatureExtractor()
    normal_vectors = extractor.extract(normal_events)
    attack_vectors = extractor.extract(attack_events)
    # 40 normal sessions + 1 attack chain.
    assert len(normal_vectors) == 40
    assert len(attack_vectors) == 1
    assert attack_vectors[0].chain_key == "4242"


def test_attack_features_are_distinct(normal_events, attack_events):
    extractor = FeatureExtractor()
    attack = extractor.extract(attack_events)[0]
    # Hard signals that never occur in the normal baseline.
    assert attack.values["tmp_execs"] > 0
    assert attack.values["suspicious_ports"] > 0
    assert attack.values["privilege_escalations"] > 0
    assert attack.values["script_interpreters"] >= 2


def test_vector_order_matches_feature_names(normal_events):
    extractor = FeatureExtractor()
    vector = extractor.extract(normal_events)[0]
    assert len(vector.to_vector()) == len(FEATURE_NAMES)
    assert vector.keys() == FEATURE_NAMES


def test_basename_property(normal_events):
    extractor = FeatureExtractor()
    vector = extractor.extract(normal_events)[0]
    assert vector.basename
    assert vector.basename == vector.exe.split("/")[-1]


def test_empty_extraction():
    assert FeatureExtractor().extract([]) == []
