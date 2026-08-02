"""Tests for the response engine."""

from __future__ import annotations

from backend.core.analysis import ActionStatus
from backend.detection.isolation_forest import IsolationForestDetector
from backend.explainability.explainer import RuleBasedExplainer
from backend.features.extractor import FeatureExtractor
from backend.response.actions import ActionExecutor, ResponseActionBuilder
from backend.response.approval import ApprovalGate
from backend.response.decision import DecisionEngine


def _attack_context(normal_events, attack_events):
    extractor = FeatureExtractor()
    detector = IsolationForestDetector().fit(extractor.extract(normal_events))
    vector = extractor.extract(attack_events)[0]
    result = detector.predict(vector)
    explanation = RuleBasedExplainer().explain(vector, result)
    return vector, result, explanation


def test_decision_recommends_remediation(normal_events, attack_events):
    vector, result, explanation = _attack_context(normal_events, attack_events)
    actions = DecisionEngine().decide(vector, result, explanation)
    action_types = {a.action_type for a in actions}
    assert "kill_process" in action_types
    assert "block_ip" in action_types
    assert "quarantine_file" in action_types


def test_decision_empty_when_not_flagged(normal_events):
    extractor = FeatureExtractor()
    detector = IsolationForestDetector().fit(extractor.extract(normal_events))
    vector = extractor.extract(normal_events)[0]
    result = detector.predict(vector)
    explanation = RuleBasedExplainer().explain(vector, result)
    assert DecisionEngine().decide(vector, result, explanation) == []


def test_approval_gate_requires_human_for_destructive(normal_events, attack_events):
    vector, result, explanation = _attack_context(normal_events, attack_events)
    actions = DecisionEngine().decide(vector, result, explanation)
    gate = ApprovalGate(auto_approve_destructive=False)
    processed = [gate.process(a) for a in actions]
    assert all(a.status == ActionStatus.PENDING_APPROVAL for a in processed)


def test_approval_gate_auto_approves_when_enabled(normal_events, attack_events):
    vector, result, explanation = _attack_context(normal_events, attack_events)
    actions = DecisionEngine().decide(vector, result, explanation)
    gate = ApprovalGate(auto_approve_destructive=True)
    processed = [gate.process(a) for a in actions]
    assert all(a.status == ActionStatus.APPROVED for a in processed)


def test_executor_dry_run_marks_executed(normal_events, attack_events):
    vector, result, explanation = _attack_context(normal_events, attack_events)
    action = DecisionEngine().decide(vector, result, explanation)[0]
    gate = ApprovalGate(auto_approve_destructive=False)
    gate.process(action)
    gate.approve(action)
    executed = ActionExecutor(dry_run=True).execute(action)
    assert executed.status == ActionStatus.EXECUTED
    assert executed.target["pid"] == vector.pid


def test_executor_refuses_unapproved(normal_events, attack_events):
    vector, result, explanation = _attack_context(normal_events, attack_events)
    action = DecisionEngine().decide(vector, result, explanation)[0]
    executed = ActionExecutor(dry_run=True).execute(action)
    assert executed.status == ActionStatus.RECOMMENDED  # untouched


def test_builder_targets():
    action = ResponseActionBuilder.kill_process(42, "bash", "r")
    assert action.target == {"pid": 42, "exe": "bash"}
    assert action.requires_approval is True
