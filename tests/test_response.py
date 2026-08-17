"""Tests for the response engine."""

from __future__ import annotations

import json
import logging

from backend.core.analysis import ActionStatus, ResponseAction
from backend.detection.isolation_forest import IsolationForestDetector
from backend.explainability.explainer import RuleBasedExplainer
from backend.features.extractor import FeatureExtractor
from backend.response.actions import ActionExecutor, ResponseActionBuilder
from backend.response.approval import ApprovalGate
from backend.response.containment import ContainmentManager, SystemRunner
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


# -- Fix 5: approval state validation ---------------------------------------

def test_approve_ignores_non_pending_action():
    gate = ApprovalGate()
    action = ResponseAction(
        action_type="kill_process", description="d", destructive=True,
        requires_approval=True, target={"pid": 1}, status=ActionStatus.APPROVED,
    )
    gate.approve(action)
    assert action.status == ActionStatus.APPROVED  # unchanged


def test_reject_ignores_non_pending_action():
    gate = ApprovalGate()
    action = ResponseAction(
        action_type="kill_process", description="d", destructive=True,
        requires_approval=True, target={"pid": 1}, status=ActionStatus.EXECUTED,
    )
    gate.reject(action)
    assert action.status == ActionStatus.EXECUTED  # unchanged


def test_approve_reject_only_pending(caplog):
    gate = ApprovalGate()
    action = ResponseAction(
        action_type="block_ip", description="d", destructive=True,
        requires_approval=True, target={"ip": "1.2.3.4"}, status=ActionStatus.RECOMMENDED,
    )
    with caplog.at_level(logging.WARNING, logger="guardianos.response.approval"):
        gate.approve(action)
    assert action.status == ActionStatus.RECOMMENDED
    assert "status recommended" in caplog.text


# -- Fix 4: bounded reports deque -------------------------------------------

def test_reports_bounded_deque():
    from collections import deque

    from backend.core.config import AppConfig
    from backend.pipeline import GuardianPipeline
    from backend.telemetry.demo_generator import DemoGenerator

    config = AppConfig.load()
    pipeline = GuardianPipeline(config, telemetry=DemoGenerator("normal", speed=1e6))
    assert isinstance(pipeline.reports, deque)
    assert pipeline.reports.maxlen == 1000
    pipeline.stop()


# -- Fix 6: containment rollback persistence --------------------------------

class _FakeRunner(SystemRunner):
    """In-memory runner for testing."""
    def __init__(self):
        self.resumed_pids = []
        self.moved = []

    def run(self, argv):
        return 0

    def move(self, src, dst):
        self.moved.append((src, dst))

    def suspend(self, pid):
        pass

    def resume(self, pid):
        self.resumed_pids.append(pid)

    def terminate(self, pid):
        pass

    @property
    def platform(self):
        return "linux"


def test_containment_persists_and_loads(tmp_path):
    persist_path = tmp_path / "containment.jsonl"
    runner = _FakeRunner()

    manager = ContainmentManager(
        dry_run=False, runner=runner, persist_path=persist_path,
    )

    action = ResponseAction(
        action_type="freeze_process", description="freeze", destructive=False,
        requires_approval=False, target={"pid": 1234},
    )
    entry = manager.apply(action, report_id="rpt-1")
    assert entry is not None
    assert entry.reversible is True

    # Persisted file exists and has one line.
    assert persist_path.exists()
    lines = persist_path.read_text().strip().splitlines()
    assert len(lines) == 1
    data = json.loads(lines[0])
    assert data["action_type"] == "freeze_process"
    assert data["report_id"] == "rpt-1"

    # Load into a fresh manager — entries restored, undo closures reconstructed.
    manager2 = ContainmentManager(
        dry_run=False, runner=runner, persist_path=persist_path,
    )
    assert len(manager2.entries) == 1
    loaded = manager2.entries[0]
    assert loaded.action_type == "freeze_process"
    assert loaded.target["pid"] == 1234
    assert loaded.report_id == "rpt-1"
    assert loaded.undo is not None  # reconstructed

    # Rollback works via reconstructed undo.
    assert manager2.rollback(loaded) is True
    assert 1234 in runner.resumed_pids


def test_containment_kill_no_undo_on_load(tmp_path):
    persist_path = tmp_path / "containment.jsonl"
    runner = _FakeRunner()

    manager = ContainmentManager(
        dry_run=True, runner=runner, persist_path=persist_path,
    )
    action = ResponseAction(
        action_type="kill_process", description="kill", destructive=True,
        requires_approval=True, target={"pid": 99},
    )
    manager.apply(action, report_id="rpt-2")

    manager2 = ContainmentManager(
        dry_run=True, runner=runner, persist_path=persist_path,
    )
    loaded = manager2.entries[0]
    assert loaded.reversible is False
    assert loaded.undo is None
    assert manager2.rollback(loaded) is False
