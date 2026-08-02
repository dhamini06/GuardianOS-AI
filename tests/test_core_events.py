"""Tests for the core event and analysis models."""

from __future__ import annotations

from backend.core.analysis import (
    ActionStatus,
    MitreReference,
    ResponseAction,
    Severity,
    ThreatReport,
)
from backend.core.events import EventKind, KernelEvent, make_event


def test_event_roundtrip_dict():
    event = make_event(
        EventKind.PROCESS_CREATED,
        pid=123,
        ppid=1,
        exe="/usr/bin/python3",
        cmdline=("python3", "-c", "x"),
        username="dev",
        session_leader=999,
    )
    restored = KernelEvent.from_dict(event.to_dict())
    assert restored == event


def test_event_basename():
    event = make_event(EventKind.EXEC, pid=1, ppid=0, exe="/tmp/payload.sh")
    assert event.basename == "payload.sh"


def test_chain_key_uses_session_leader():
    event = make_event(EventKind.EXEC, pid=1, ppid=1, exe="/bin/bash", session_leader=4242)
    from backend.core.events import event_chain_key

    assert event_chain_key(event) == "4242:bash"


def test_severity_ordering():
    assert Severity.CRITICAL.value == "critical"


def test_mitre_reference_url_format():
    ref = MitreReference("T1059.004", "Unix Shell", "Execution", "https://attack.mitre.org/techniques/T1059/004")
    assert "T1059/004" in ref.url
    assert "T1059.004" in str(ref)


def test_response_action_to_dict():
    action = ResponseAction(
        action_type="kill_process",
        description="x",
        destructive=True,
        requires_approval=True,
    )
    data = action.to_dict()
    assert data["status"] == ActionStatus.RECOMMENDED.value
    assert data["destructive"] is True


def test_threat_report_serialisation(app_config):
    from backend.detection.isolation_forest import IsolationForestDetector
    from backend.explainability.explainer import RuleBasedExplainer
    from backend.features.extractor import FeatureExtractor
    from backend.telemetry.demo_generator import build_scenario

    normal = [e for _, e in build_scenario("normal", normal_runs=10)]
    attack = [e for _, e in build_scenario("attack")]
    extractor = FeatureExtractor()
    detector = IsolationForestDetector().fit(extractor.extract(normal))
    vector = extractor.extract(attack)[0]
    result = detector.predict(vector)
    explanation = RuleBasedExplainer().explain(vector, result)
    report = ThreatReport(report_id="abc", timestamp=1.0, detection=result, explanation=explanation)
    data = report.to_dict()
    assert data["report_id"] == "abc"
    assert data["detection"]["flagged"] is True
