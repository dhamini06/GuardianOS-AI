"""Tests for the analyst feedback loop (M2 baseline lifecycle)."""

from __future__ import annotations

import pytest

from backend.features.extractor import FeatureExtractor
from backend.feedback.learning import reweight_baseline
from backend.feedback.ledger import FeedbackLedger
from backend.telemetry.demo_generator import build_scenario


def _vectors():
    events = [e for _, e in build_scenario("normal", normal_runs=6)]
    return FeatureExtractor().extract(events)


def test_record_and_lookup():
    ledger = FeedbackLedger()
    assert ledger.record("1:bash", "malicious", report_id="r1")
    assert ledger.verdict_for("1:bash") == "malicious"
    assert ledger.malicious_keys == {"1:bash"}


def test_record_dedupes_per_chain():
    ledger = FeedbackLedger()
    assert ledger.record("1:bash", "malicious")
    assert not ledger.record("1:bash", "malicious")
    assert ledger.record("1:bash", "benign")
    assert ledger.verdict_for("1:bash") == "benign"


def test_invalid_verdict_rejected():
    ledger = FeedbackLedger()
    with pytest.raises(ValueError, match="verdict"):
        ledger.record("1:bash", "suspicious")


def test_ledger_persists_and_reloads(tmp_path):
    path = tmp_path / "feedback.jsonl"
    a = FeedbackLedger(path)
    a.record("1:bash", "malicious", report_id="r1", note="confirmed C2")
    a.record("2:python3", "benign", report_id="r2")

    b = FeedbackLedger(path)
    assert b.verdict_for("1:bash") == "malicious"
    assert b.verdict_for("2:python3") == "benign"
    assert b.summary() == {"benign": 1, "malicious": 1}


def test_reweight_drops_malicious_chains():
    vectors = _vectors()
    ledger = FeedbackLedger()
    ledger.record(vectors[0].chain_key, "malicious")
    kept = reweight_baseline(vectors, ledger)
    assert all(v.chain_key != vectors[0].chain_key for v in kept)
    assert len(kept) == len(vectors) - 1


def test_reweight_keeps_benign_chains():
    vectors = _vectors()
    ledger = FeedbackLedger()
    ledger.record(vectors[0].chain_key, "benign")
    assert len(reweight_baseline(vectors, ledger)) == len(vectors)


def test_reweight_without_verdicts_is_identity():
    vectors = _vectors()
    assert reweight_baseline(vectors, FeedbackLedger()) == vectors
